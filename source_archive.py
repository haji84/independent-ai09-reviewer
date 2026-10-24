"""Read the immutable source as data only. No filesystem or code execution.

Supported subset: single-disk non-ZIP64 ZIP, STORED/raw DEFLATE, regular files
and empty directories. Unsupported originals block; never repair/recompress.
This is not a frozen-plan adapter or authorization to access private data.
"""
import dataclasses
import hashlib
import stat
import struct
import types
import unicodedata
import zlib

from data_driver import GateError, require

FROZEN_SHA = '9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5'
MAX_ARCHIVE = 5_000_000
MAX_EXPANDED = 10_000_000
MAX_PLAN = 2_000_000
MAX_ENTRIES = 80
FILE_COUNT = 47
BLOCK = 65_536


@dataclasses.dataclass(frozen=True, repr=False)
class SourceFile:
    path: str
    content: bytes
    sha: str

    def __repr__(self):
        return 'SourceFile()'


@dataclasses.dataclass(frozen=True)
class SourceArchive:
    archive_sha: str
    files: types.MappingProxyType = dataclasses.field(repr=False)
    directories: tuple = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True)
class OpaquePlan:
    content: bytes = dataclasses.field(repr=False)
    sha: str = dataclasses.field(repr=False)


def preserve_original_plan(raw):
    """Identify exact opaque bytes, NOT authentication or schema validation."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PLAN, 'PLAN_SIZE_OR_TYPE')
    return OpaquePlan(raw, hashlib.sha256(raw).hexdigest())


def _extra(raw):
    position = 0
    while position < len(raw):
        require(position+4 <= len(raw), 'INVALID_SOURCE_ZIP')
        tag, length = struct.unpack_from('<HH', raw, position)
        require(tag != 1, 'UNSUPPORTED_SOURCE_ZIP')  # ZIP64
        position += 4+length
        require(position <= len(raw), 'INVALID_SOURCE_ZIP')


def _central(raw):
    """Walk checked central records before allocating any filename/file objects."""
    candidates = []
    start = max(0, len(raw)-65_557)
    position = raw.find(b'PK\x05\x06', start)
    while position != -1:
        if position+22 <= len(raw):
            end = struct.unpack_from('<4s4H2LH', raw, position)
            if position+22+end[7] == len(raw):
                candidates.append((position,end))
        position = raw.find(b'PK\x05\x06', position+1)
    require(len(candidates) == 1, 'INVALID_SOURCE_ZIP')
    end_pos, end = candidates[0]
    _, disk, central_disk, disk_count, count, size, offset, comment = end
    require(b'PK\x05\x06' not in raw[end_pos+22:], 'UNSUPPORTED_SOURCE_ZIP')
    require(disk == central_disk == 0 and disk_count == count and
            0 < count <= MAX_ENTRIES and size != 0xffffffff and offset != 0xffffffff,
            'UNSUPPORTED_SOURCE_ZIP')
    require(offset+size == end_pos, 'INVALID_SOURCE_ZIP')
    records = []
    position = offset
    while position < end_pos:
        require(len(records) < count and position+46 <= end_pos and
                raw[position:position+4] == b'PK\x01\x02', 'INVALID_SOURCE_ZIP')
        flags, method = struct.unpack_from('<HH', raw, position+8)
        crc, compressed, expanded = struct.unpack_from('<LLL', raw, position+16)
        name_len, extra_len, comment_len, member_disk = struct.unpack_from('<4H', raw, position+28)
        attrs, local_offset = struct.unpack_from('<LL', raw, position+38)
        next_pos = position+46+name_len+extra_len+comment_len
        require(0 < name_len <= 1024 and next_pos <= end_pos, 'INVALID_SOURCE_ZIP')
        require(member_disk == 0 and method in (0,8) and flags & ~0x80e == 0 and
                not (method == 0 and flags & 6), 'UNSUPPORTED_SOURCE_ZIP')
        require(expanded <= MAX_EXPANDED and compressed <= MAX_ARCHIVE and
                local_offset < offset, 'SOURCE_SIZE_LIMIT')
        name = raw[position+46:position+46+name_len]
        _extra(raw[position+46+name_len:position+46+name_len+extra_len])
        records.append((name, flags, method, crc, compressed, expanded, attrs, local_offset))
        position = next_pos
    require(position == end_pos and len(records) == count, 'INVALID_SOURCE_ZIP')
    return offset, records


def _name(raw_name, flags, attrs):
    name = raw_name.decode('utf-8' if flags & 0x800 else 'cp437')
    directory = name.endswith('/')
    clean = name[:-1] if directory else name
    require(clean and not any(unicodedata.category(c) in ('Cc','Cf','Cs') for c in clean) and
            not any(c in clean for c in '\\:') and
            all(part not in ('','.','..') for part in clean.split('/')), 'INVALID_SOURCE_PATH')
    kind = stat.S_IFMT(attrs >> 16)
    require(kind in ((0,stat.S_IFDIR) if directory else (0,stat.S_IFREG)),
            'UNSUPPORTED_SOURCE_MEMBER')
    return name, clean, directory


def _local(raw, central_start, record):
    name, flags, method, crc, compressed, expanded, attrs, offset = record
    require(offset+30 <= central_start and raw[offset:offset+4] == b'PK\x03\x04',
            'INVALID_SOURCE_ZIP')
    local_flags, local_method = struct.unpack_from('<HH', raw, offset+6)
    local_crc, local_compressed, local_expanded = struct.unpack_from('<LLL',raw,offset+14)
    name_len, extra_len = struct.unpack_from('<HH',raw,offset+26)
    data_start = offset+30+name_len+extra_len
    data_end = data_start+compressed
    require(local_flags == flags and local_method == method and
            data_end <= central_start and raw[offset+30:offset+30+name_len] == name,
            'INVALID_SOURCE_ZIP')
    _extra(raw[offset+30+name_len:data_start])
    if flags & 8:
        require(local_crc in (0,crc) and local_compressed in (0,compressed) and
                local_expanded in (0,expanded), 'INVALID_SOURCE_ZIP')
        descriptor = data_end
        if raw[descriptor:descriptor+4] == b'PK\x07\x08':
            descriptor += 4
        require(descriptor+12 <= central_start and
                struct.unpack_from('<LLL',raw,descriptor) == (crc,compressed,expanded),
                'INVALID_SOURCE_ZIP')
        member_end = descriptor+12
    else:
        require((local_crc,local_compressed,local_expanded) == (crc,compressed,expanded),
                'INVALID_SOURCE_ZIP')
        member_end = data_end
    return data_start, data_end, member_end


def _content(raw, start, end, method, expanded, crc):
    result = bytearray()
    observed_crc = 0

    def append(block):
        nonlocal observed_crc
        require(len(result)+len(block) <= expanded, 'SOURCE_SIZE_MISMATCH')
        result.extend(block)
        observed_crc = zlib.crc32(block, observed_crc)

    if method == 0:
        require(end-start == expanded, 'SOURCE_SIZE_MISMATCH')
        for position in range(start,end,BLOCK):
            append(raw[position:min(position+BLOCK,end)])
    else:
        decoder = zlib.decompressobj(-15)
        for position in range(start,end,BLOCK):
            pending = raw[position:min(position+BLOCK,end)]
            while pending:
                block = decoder.decompress(pending,min(BLOCK,expanded-len(result)+1))
                append(block)
                tail = decoder.unconsumed_tail
                require(not decoder.unused_data and (block or len(tail)<len(pending)),
                        'INVALID_SOURCE_DEFLATE')
                pending = tail
        while not decoder.eof:
            block = decoder.decompress(b'',min(BLOCK,expanded-len(result)+1))
            if not block:
                break
            append(block)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                'INVALID_SOURCE_DEFLATE')
    require(len(result) == expanded and observed_crc == crc, 'SOURCE_SIZE_OR_CRC_MISMATCH')
    return bytes(result)


def read_frozen_archive(raw):
    """No expected-hash override. Read exact immutable input bytes, write nothing."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE, 'ARCHIVE_SIZE_OR_TYPE')
    archive_sha = hashlib.sha256(raw).hexdigest()
    require(archive_sha == FROZEN_SHA, 'FROZEN_SOURCE_HASH_MISMATCH')
    try:
        central_start, records = _central(raw)
        prepared = []
        declarations = set()
        nodes = {}
        files = set()
        directories = set()
        total = 0
        for record in records:
            name, clean, directory = _name(record[0],record[1],record[6])
            require(clean.casefold() not in declarations, 'SOURCE_PATH_COLLISION')
            declarations.add(clean.casefold())
            parts = clean.split('/')
            for depth in range(1,len(parts)+1):
                prefix = '/'.join(parts[:depth])
                folded = prefix.casefold()
                require(folded not in nodes or nodes[folded] == prefix, 'SOURCE_PATH_COLLISION')
                nodes[folded] = prefix
                if depth < len(parts) or directory:
                    directories.add(folded)
            if directory:
                require(record[5] == 0, 'INVALID_SOURCE_DIRECTORY')
            else:
                files.add(clean.casefold())
            total += record[5]
            require(total <= MAX_EXPANDED, 'SOURCE_SIZE_LIMIT')
            start,end,member_end = _local(raw,central_start,record)
            prepared.append((record,name,directory,start,end,member_end))
        require(not files & directories, 'SOURCE_PATH_COLLISION')
        require(len(files) == FILE_COUNT, 'SOURCE_FILE_COUNT_MISMATCH')
        # Reject overlap, concatenated/self-extracting ZIPs and unexplained gaps.
        next_offset = 0
        for record,name,directory,start,end,member_end in sorted(prepared,key=lambda p:p[0][7]):
            require(record[7] == next_offset, 'INVALID_SOURCE_ZIP')
            next_offset = member_end
        require(next_offset == central_start, 'INVALID_SOURCE_ZIP')
        outputs = {}
        declared_directories = []
        for record,name,directory,start,end,member_end in prepared:
            content = _content(raw,start,end,record[2],record[5],record[3])
            if directory:
                require(content == b'', 'INVALID_SOURCE_DIRECTORY')
                declared_directories.append(name)
            else:
                outputs[name] = SourceFile(name,content,hashlib.sha256(content).hexdigest())
        return SourceArchive(archive_sha,types.MappingProxyType(outputs),tuple(declared_directories))
    except GateError:
        raise
    except (ValueError,UnicodeError,struct.error,zlib.error,OverflowError):
        raise GateError('INVALID_SOURCE_ZIP') from None
