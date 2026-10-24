"""Public ZIP fixtures only; never recompress or read the frozen subject."""
import dataclasses
import hashlib
import io
import struct
import unittest
import zipfile
import tracemalloc
from unittest.mock import patch

import source_archive as source
from data_driver import GateError


def toy_archive(changes=None, extras=(), compression=zipfile.ZIP_DEFLATED, comment=b''):
    files = {f'public/{i:03}.dat': b'PUBLIC\r\n\xff\x00\n' for i in range(47)}
    if changes:
        files.update(changes)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=compression) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        for name, content in extras:
            archive.writestr(name, content)
        archive.comment = comment
    return stream.getvalue()


def read_toy(raw):
    # A test-only patch. The public production API accepts no hash override.
    with patch.object(source,'FROZEN_SHA',hashlib.sha256(raw).hexdigest()):
        return source.read_frozen_archive(raw)


def replace_first_compressed_stream(raw, stream):
    """Keep all sizes/offsets consistent to isolate stream validation."""
    old_central=struct.unpack_from('<L',raw,len(raw)-6)[0]
    name_len,extra_len=struct.unpack_from('<HH',raw,26)
    start=30+name_len+extra_len
    old_length=struct.unpack_from('<L',raw,18)[0]
    delta=len(stream)-old_length
    changed=bytearray(raw[:start]+stream+raw[start+old_length:])
    struct.pack_into('<L',changed,18,len(stream))
    position=old_central+delta
    for index in range(47):
        if index==0:struct.pack_into('<L',changed,position+20,len(stream))
        else:
            offset=struct.unpack_from('<L',changed,position+42)[0]
            struct.pack_into('<L',changed,position+42,offset+delta)
        lengths=struct.unpack_from('<3H',changed,position+28)
        position+=46+sum(lengths)
    struct.pack_into('<L',changed,position+16,old_central+delta)
    return bytes(changed)


class SourceArchiveTest(unittest.TestCase):
    def test_production_hash_cannot_be_overridden_by_caller(self):
        raw = toy_archive()
        with self.assertRaisesRegex(GateError, '^FROZEN_SOURCE_HASH_MISMATCH$'):
            source.read_frozen_archive(raw)
        with self.assertRaises(TypeError):
            source.read_frozen_archive(raw, expected_sha=hashlib.sha256(raw).hexdigest())

    def test_exact_binary_bytes_paths_and_directory_are_preserved(self):
        raw = toy_archive(extras=[('public/', b'')])
        result = read_toy(raw)
        self.assertEqual(result.archive_sha,hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.directories,('public/',))
        self.assertEqual(len(result.files),47)
        self.assertEqual(result.files['public/000.dat'].content,b'PUBLIC\r\n\xff\x00\n')
        self.assertEqual(result.files['public/000.dat'].sha,hashlib.sha256(b'PUBLIC\r\n\xff\x00\n').hexdigest())
        self.assertNotIn('public/',repr(result))
        with self.assertRaises(TypeError): result.files['new'] = None
        with self.assertRaises(dataclasses.FrozenInstanceError): result.files['public/000.dat'].content = b'changed'

    def test_stored_empty_and_newline_variants_are_not_normalized(self):
        changes = {'public/000.dat':b'', 'public/001.dat':b'\xef\xbb\xbfline\r\nnext\n'}
        result = read_toy(toy_archive(changes,compression=zipfile.ZIP_STORED))
        for path, raw in changes.items(): self.assertEqual(result.files[path].content,raw)

    def test_opaque_plan_preservation_is_not_schema_validation(self):
        raw = b'NOT-JSON\r\n\xff\x00'
        result = source.preserve_original_plan(raw)
        self.assertEqual(result.content,raw)
        self.assertEqual(result.sha,hashlib.sha256(raw).hexdigest())
        self.assertEqual(repr(result),'OpaquePlan()')
        with self.assertRaises(dataclasses.FrozenInstanceError): result.content=b'other'
        for invalid in (b'',bytearray(b'x'),b'x'*(source.MAX_PLAN+1)):
            with self.assertRaises(GateError): source.preserve_original_plan(invalid)

    def test_unsafe_names_aliases_and_special_files_are_rejected(self):
        for extra in [('../PRIVATE-PATH',b'x'),('/absolute',b'x'),('public\\x',b'x'),
                      ('PUBLIC/000.dat',b'x'),('public/000.dat/child',b'x'),
                      ('PUBLIC/other',b'x'),('public/',b'directory-data')]:
            with self.subTest(name=extra[0]):
                with self.assertRaises(GateError) as error:
                    read_toy(toy_archive(extras=[extra]))
                self.assertNotIn(extra[0],str(error.exception))
        link = zipfile.ZipInfo('link'); link.create_system=3
        link.external_attr=0o120777<<16
        with self.assertRaises(GateError): read_toy(toy_archive(extras=[(link,b'target')]))
        raw = toy_archive().replace(b'public/000.dat',b'public/000\x00dat')
        with self.assertRaises(GateError): read_toy(raw)

    def test_entry_and_regular_file_counts_are_bounded(self):
        for raw in [toy_archive(extras=[('extra',b'x')]),
                    toy_archive(extras=[(f'dir{i}/',b'') for i in range(34)])]:
            with self.assertRaises(GateError): read_toy(raw)

    def test_eocd_inside_comment_and_ambiguous_trailing_structures_fail_closed(self):
        # A normal comment is supported; an embedded EOCD signature is rejected
        # as an explicit unsupported/ambiguous ZIP subset rather than guessed.
        self.assertEqual(len(read_toy(toy_archive(comment=b'PUBLIC comment')).files),47)
        for raw in [toy_archive(comment=b'PUBLIC PK\x05\x06 ambiguity'),
                    toy_archive()+b'trailing', toy_archive()[:-10]]:
            with self.assertRaises(GateError): read_toy(raw)

    def test_central_count_offsets_zip64_and_multidisk_are_rejected(self):
        raw = toy_archive(); end=raw.rfind(b'PK\x05\x06')
        variants=[]
        for offset, fmt, value in [(end+4,'<H',1),(end+8,'<H',46),(end+10,'<H',65535),
                                   (end+12,'<L',0xffffffff),(end+16,'<L',1)]:
            changed=bytearray(raw); struct.pack_into(fmt,changed,offset,value);variants.append(bytes(changed))
        for changed in variants:
            with self.assertRaises(GateError): read_toy(changed)

    def test_local_header_method_filename_encryption_overlap_and_crc_are_checked(self):
        raw=toy_archive(); central=raw.find(b'PK\x01\x02')
        variants=[]
        for offset, fmt, value in [(8,'<H',0),(central+8,'<H',1),(central+42,'<L',1),
                                   (central+16,'<L',0),(central+20,'<L',999999)]:
            changed=bytearray(raw);struct.pack_into(fmt,changed,offset,value);variants.append(bytes(changed))
        changed=bytearray(raw);changed[30]=ord('X');variants.append(bytes(changed))
        for changed in variants:
            with self.assertRaises(GateError):read_toy(changed)

    def test_unsupported_compression_and_forged_short_length_are_rejected(self):
        for method in (zipfile.ZIP_BZIP2,zipfile.ZIP_LZMA):
            with self.assertRaises(GateError):read_toy(toy_archive(compression=method))
        raw=bytearray(toy_archive({'public/000.dat':b'A'*2_000_000}))
        central=raw.find(b'PK\x01\x02')
        struct.pack_into('<L',raw,22,1)
        struct.pack_into('<L',raw,central+24,1)
        tracemalloc.start()
        try:
            with self.assertRaises(GateError):read_toy(bytes(raw))
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertLess(peak,1_000_000)

    def test_crc_stream_eof_and_no_trailing_compressed_data_are_required(self):
        original=toy_archive()
        central=original.find(b'PK\x01\x02')
        changed=bytearray(original)
        struct.pack_into('<L',changed,14,0)
        struct.pack_into('<L',changed,central+16,0)
        with self.assertRaisesRegex(GateError,'^SOURCE_SIZE_OR_CRC_MISMATCH$'):
            read_toy(bytes(changed))
        name_len,extra_len=struct.unpack_from('<HH',original,26)
        start=30+name_len+extra_len
        length=struct.unpack_from('<L',original,18)[0]
        compressed=original[start:start+length]
        for stream in (compressed+b'PRIVATE-TRAILING',compressed[:-1]):
            with self.subTest(length=len(stream)):
                with self.assertRaisesRegex(GateError,'^INVALID_SOURCE_DEFLATE$'):
                    read_toy(replace_first_compressed_stream(original,stream))

    def test_entry_data_descriptors_from_nonseekable_zip_writer_are_supported(self):
        class Streaming(io.BytesIO):
            def seekable(self):return False
            def seek(self,*args):raise OSError('not seekable')
        stream=Streaming()
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for index in range(47):archive.writestr(f'public/{index:03}.dat',b'PUBLIC\n')
        result=read_toy(stream.getvalue())
        self.assertEqual(result.files['public/046.dat'].content,b'PUBLIC\n')


if __name__=='__main__':unittest.main()
