#!/usr/bin/env python3
"""Public-safe AI09 bridge: encrypted input and encrypted evidence only."""
import argparse, base64, hashlib, io, os, re, stat, sys, zipfile
from pathlib import Path, PurePosixPath
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC=b'AI09SEAL1\x00'
FROZEN_SHA='9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5'
SUBJECT='universal-ai-development-v0.5-review-candidate.zip'
MAX_ENCRYPTED=5_000_000
MAX_EXPANDED=10_000_000
MAX_ENTRIES=80
READ_BLOCK=65_536
MAX_EVIDENCE_FILE=100_000

def key_from_env():
    value=os.environ.get('AI09_BUNDLE_KEY_B64','')
    if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',value):
        raise ValueError('MISSING_OR_INVALID_BUNDLE_SECRET')
    key=base64.b64decode(value,validate=True)
    if len(key)!=32: raise ValueError('INVALID_BUNDLE_SECRET_LENGTH')
    return key

def derived_key(master,purpose):
    return HKDF(algorithm=hashes.SHA256(),length=32,
                salt=b'AI09-SEPARATED-KEYS-v1',info=purpose).derive(master)

def seal(content,master,purpose):
    if len(content)+len(MAGIC)+12+16>MAX_ENCRYPTED:
        raise ValueError('OVERSIZE_ENCRYPTED_PAYLOAD')
    nonce=os.urandom(12)
    return MAGIC+nonce+AESGCM(derived_key(master,purpose)).encrypt(
        nonce,content,MAGIC+purpose)

def unseal(blob,master,purpose):
    if not blob.startswith(MAGIC) or not 23<=len(blob)<=MAX_ENCRYPTED:
        raise ValueError('INVALID_ENCRYPTED_PAYLOAD')
    nonce=blob[len(MAGIC):len(MAGIC)+12]
    return AESGCM(derived_key(master,purpose)).decrypt(
        nonce,blob[len(MAGIC)+12:],MAGIC+purpose)

def safe_member(item):
    if item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
        raise ValueError('UNSUPPORTED_BUNDLE_COMPRESSION')
    name=item.filename
    parts=name.split('/')
    mode=item.external_attr>>16
    if (item.orig_filename!=name or any(ord(c)<32 or ord(c)==127 for c in name) or
        not name or name.startswith('/') or name.endswith('/') or
        '\\' in name or ':' in name or any(x in ('','.','..') for x in parts) or
        PurePosixPath(name).as_posix()!=name):
        raise ValueError('UNSAFE_BUNDLE_PATH')
    if item.is_dir() or (mode and stat.S_IFMT(mode) not in [0,stat.S_IFREG]):
        raise ValueError('UNSUPPORTED_BUNDLE_MEMBER')
    if item.file_size>MAX_EXPANDED:
        raise ValueError('OVERSIZE_BUNDLE_MEMBER')

def open_bundle(encrypted_file,destination):
    if encrypted_file.stat().st_size>MAX_ENCRYPTED:
        raise ValueError('OVERSIZE_ENCRYPTED_BUNDLE')
    payload=unseal(encrypted_file.read_bytes(),key_from_env(),b'FROZEN-SOURCE-BUNDLE')
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        infos=z.infolist()
        if not infos or len(infos)>MAX_ENTRIES:
            raise ValueError('BAD_BUNDLE_MEMBER_COUNT')
        names=[x.filename for x in infos]
        if len(set(names))!=len(names) or len(set(x.casefold() for x in names))!=len(names):
            raise ValueError('DUPLICATE_BUNDLE_ENTRY')
        folded={name.casefold() for name in names}
        for item in infos:
            safe_member(item)
            if any(parent.as_posix().casefold() in folded
                   for parent in PurePosixPath(item.filename).parents):
                raise ValueError('BUNDLE_FILE_DIRECTORY_COLLISION')
        if sum(item.file_size for item in infos)>MAX_EXPANDED:
            raise ValueError('OVERSIZE_BUNDLE_EXPANSION')
        extracted={}
        total=0
        for item in infos:
            content=bytearray()
            with z.open(item) as entry:
                while True:
                    block=entry.read(READ_BLOCK)
                    if not block:break
                    content.extend(block)
                    total+=len(block)
                    if len(content)>item.file_size or total>MAX_EXPANDED:
                        raise ValueError('OVERSIZE_BUNDLE_EXPANSION')
            if len(content)!=item.file_size:raise ValueError('BUNDLE_SIZE_MISMATCH')
            extracted[item.filename]=bytes(content)
    subject=extracted.get(SUBJECT)
    if subject is None or hashlib.sha256(subject).hexdigest()!=FROZEN_SHA:
        raise ValueError('FROZEN_SUBJECT_INTEGRITY_FAILURE')
    if destination.exists(): raise ValueError('DESTINATION_ALREADY_EXISTS')
    destination.mkdir(mode=0o700,parents=True)
    for name,content in extracted.items():
        p=destination/name
        p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with p.open('xb') as f:f.write(content)
        p.chmod(0o600)
    return len(extracted)

def seal_evidence(source,output):
    if not source.is_dir() or source.is_symlink():
        raise ValueError('INVALID_EVIDENCE_SOURCE')
    outputs=[]
    total=0
    for p in sorted(source.iterdir()):
        if (not p.is_file() or p.is_symlink() or
            not re.fullmatch(r'chunk-[0-9]{3}\.json|model-inventory\.json|pilot-summary\.json',p.name)):
            raise ValueError('UNEXPECTED_EVIDENCE_FILE')
        if p.name.startswith('chunk-') and int(p.name[6:9])>=104:
            raise ValueError('UNEXPECTED_CHUNK_NUMBER')
        if p.stat().st_size>MAX_EVIDENCE_FILE:
            raise ValueError('OVERSIZE_EVIDENCE_FILE')
        with p.open('rb') as f:content=f.read(MAX_EVIDENCE_FILE+1)
        total+=len(content)
        if len(content)>MAX_EVIDENCE_FILE or total>MAX_EXPANDED:
            raise ValueError('OVERSIZE_EVIDENCE_FILE')
        outputs.append((p.name,content))
    if not outputs or not any(name.startswith('chunk-') for name,_ in outputs):
        raise ValueError('NO_REAL_MODEL_RECEIPTS')
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,content in outputs:z.writestr(name,content)
    encrypted=seal(mem.getvalue(),key_from_env(),b'CONFIDENTIAL-REVIEW-EVIDENCE')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('xb') as f:
        f.write(encrypted)
    output.chmod(0o600)
    return len(outputs)

def main():
    parser=argparse.ArgumentParser()
    subs=parser.add_subparsers(dest='cmd',required=True)
    dec=subs.add_parser('open-bundle')
    dec.add_argument('--ciphertext',required=True)
    dec.add_argument('--destination',required=True)
    enc=subs.add_parser('seal-evidence')
    enc.add_argument('--source',required=True)
    enc.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        if args.cmd=='open-bundle':
            count=open_bundle(Path(args.ciphertext),Path(args.destination))
            print(f'ENCRYPTED_BUNDLE_VERIFIED members={count}; source content not logged')
        else:
            count=seal_evidence(Path(args.source),Path(args.output))
            print(f'PRIVATE_EVIDENCE_SEALED files={count}; content not logged')
        return 0
    except Exception:
        print('SEALED_REVIEW_GATE_BLOCKED',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
