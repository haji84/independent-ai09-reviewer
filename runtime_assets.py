"""Pinned PUBLIC Ollama assets. Never execute extracted code on the host."""
import hashlib
import os
import pathlib
import posixpath
import re
import selectors
import subprocess
import sys
import tarfile
import time
import unicodedata
import urllib.parse
import urllib.request

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))  # reviewed public code
from data_driver import GateError, parse_json, require

OLLAMA_VERSION='0.34.0'
OLLAMA_SHA='cf95886728959aa09910bb34de5cca1cc5a8f68003b5597197d3f2c2d57c0804'
OLLAMA_SIZE=1_433_537_033
OLLAMA_URL='https://github.com/ollama/ollama/releases/download/v0.34.0/ollama-linux-amd64.tar.zst'
MODEL_SHA='8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7'
MANIFEST_URL='https://registry.ollama.ai/v2/library/qwen3/manifests/1.7b'
MANIFEST_SIZE=859
MODEL_CDN='dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com'
MAX_CPU_BYTES=256*1024*1024
MAX_TAR_BYTES=8*1024*1024*1024
BLOCK=65536


def remaining(deadline, maximum=600):
    value=min(maximum,deadline-time.monotonic())
    require(value>0,'PUBLIC_RUNTIME_DEADLINE')
    return value


def allowed_url(url, redirect=False):
    try:
        parsed=urllib.parse.urlsplit(url)
        if (parsed.scheme!='https' or parsed.username or parsed.password or
            parsed.port not in (None,443) or parsed.fragment):return False
        if url==OLLAMA_URL or url==MANIFEST_URL:return True
        if parsed.hostname=='registry.ollama.ai':
            return re.fullmatch('/v2/library/qwen3/blobs/sha256:[0-9a-f]{64}',parsed.path) is not None and not parsed.query
        return redirect and (parsed.hostname==MODEL_CDN or
            (parsed.hostname=='release-assets.githubusercontent.com' and
             parsed.path.startswith('/github-production-release-asset/')))
    except ValueError:return False


def model_blobs(raw):
    require(type(raw) is bytes and len(raw)==MANIFEST_SIZE and
            hashlib.sha256(raw).hexdigest()==MODEL_SHA,'MODEL_MANIFEST_MISMATCH')
    value=parse_json(raw)
    entries=[value['config'],*value['layers']]
    require(value['schemaVersion']==2 and len(entries)==5,'MODEL_MANIFEST_MISMATCH')
    result=[]
    for entry in entries:
        digest=entry['digest'];size=entry['size']
        require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}',digest) and
                type(size) is int and 0<size<=1_500_000_000,'MODEL_MANIFEST_MISMATCH')
        result.append((digest[7:],size))
    require(len(set(d for d,_ in result))==len(result),'MODEL_MANIFEST_MISMATCH')
    return tuple(result)


def validate_inventory(version_raw,tags_raw):
    version=parse_json(version_raw);tags=parse_json(tags_raw)
    require(type(version) is dict and version.get('version')==OLLAMA_VERSION and
            type(tags) is dict and type(tags.get('models')) is list and len(tags['models'])==1,
            'PUBLIC_MODEL_INVENTORY_MISMATCH')
    model=tags['models'][0]
    require(type(model) is dict and model.get('name')=='qwen3:1.7b' and
            model.get('digest')==MODEL_SHA,'PUBLIC_MODEL_INVENTORY_MISMATCH')


def verify_file(path, size, digest, deadline):
    remaining(deadline)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size==size,'PUBLIC_ASSET_MISMATCH')
    actual=hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            remaining(deadline)
            block=stream.read(BLOCK)
            remaining(deadline)
            if not block:break
            actual.update(block)
            remaining(deadline)
    require(actual.hexdigest()==digest,'PUBLIC_ASSET_MISMATCH')
    remaining(deadline)


def _download(url, path, size, digest):
    require(allowed_url(url),'PUBLIC_ASSET_URL_BLOCKED')
    class Redirects(urllib.request.HTTPRedirectHandler):
        count=0
        def redirect_request(self,request,response,code,message,headers,newurl):
            self.count+=1
            require(self.count<=3 and allowed_url(newurl,True),'PUBLIC_ASSET_URL_BLOCKED')
            return super().redirect_request(request,response,code,message,headers,newurl)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirects())
    total=0;actual=hashlib.sha256()
    with opener.open(url,timeout=15) as response,path.open('xb') as output:
        while block:=response.read1(BLOCK):
            total+=len(block)
            require(total<=size,'PUBLIC_ASSET_SIZE_LIMIT')
            actual.update(block);output.write(block)
    require(total==size and actual.hexdigest()==digest,'PUBLIC_ASSET_MISMATCH')
    path.chmod(0o444)


def download(url,path,size,digest,deadline):
    # A separate credential-free child gives headers/body/redirects one hard
    # total timeout; urllib's per-socket timeout alone is not a wall-time bound.
    child_env={'PATH':os.defpath,'LD_LIBRARY_PATH':str(pathlib.Path(sys.base_prefix)/'lib')}
    if os.name=='nt':child_env['SYSTEMROOT']=os.environ['SYSTEMROOT']  # Windows TLS runtime, no credentials
    result=subprocess.run([sys.executable,'-I',str(pathlib.Path(__file__).resolve()),
                           'download',url,str(path),str(size),digest],
                          env=child_env,stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          timeout=remaining(deadline,240))
    require(result.returncode==0,'PUBLIC_ASSET_DOWNLOAD_FAILED')
    verify_file(path,size,digest,deadline)


def _name(name):
    while name.startswith('./'):name=name[2:]
    require(name and not name.startswith('/') and '\\' not in name and ':' not in name and
            all(x not in ('','.','..') for x in name.rstrip('/').split('/')) and
            not any(unicodedata.category(c) in ('Cc','Cf','Cs') for c in name),'PUBLIC_TAR_PATH')
    return name.rstrip('/')


def _selected(name):
    parts=name.split('/')
    cpu_names=('libggml-base.so','libggml-cpu','libggml.so','libllama.so','libmtmd.so',
               'libllama-server-impl.so','libllama-common.so',
               'libgomp.so','libstdc++.so','libgcc_s.so','libomp.so','libopenblas.so')
    return (name=='bin/ollama' or (parts[:2]==['lib','ollama'] and
            ((len(parts)==3 and (parts[2] in ('llama-server','GO_LICENSE') or
                                parts[2].startswith(cpu_names))) or
             (len(parts)>3 and parts[2].startswith('cpu_')))))


def cpu_files(stream,deadline):
    """A bounded TAR subset, rejecting PAX/longname before payload allocation."""
    consumed=0;count=0;selected_size=0;files={};aliases={};kinds={}
    def read(count):
        nonlocal consumed
        result=bytearray()
        while len(result)<count:
            remaining(deadline)
            block=stream.read(min(BLOCK,count-len(result)))
            if not block:break
            consumed+=len(block)
            require(consumed<=MAX_TAR_BYTES,'PUBLIC_TAR_LIMIT')
            result.extend(block)
        return bytes(result)
    while True:
        header=read(512)
        require(len(header)==512,'PUBLIC_TAR_TRUNCATED')
        if header==bytes(512):
            require(read(512)==bytes(512),'PUBLIC_TAR_TERMINATOR')
            while tail:=read(BLOCK):require(not any(tail),'PUBLIC_TAR_TRAILING')
            break
        count+=1;require(count<=10000,'PUBLIC_TAR_LIMIT')
        try:item=tarfile.TarInfo.frombuf(header,'utf-8','strict')
        except (tarfile.HeaderError,UnicodeError):raise GateError('PUBLIC_TAR_HEADER') from None
        require(item.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE,tarfile.SYMTYPE),
                'PUBLIC_TAR_UNSUPPORTED')
        if item.isdir() and item.name in ('.','./'):
            require(item.size==0,'PUBLIC_TAR_HEADER');continue
        name=_name(item.name)
        require(name not in kinds,'PUBLIC_TAR_DUPLICATE');kinds[name]=item.type
        require(0<=item.size<=MAX_TAR_BYTES and (item.isfile() or item.size==0),'PUBLIC_TAR_LIMIT')
        selected=_selected(name) and not item.isdir()
        if selected and item.issym():
            require(not item.linkname.startswith('/') and '\\' not in item.linkname,'PUBLIC_TAR_ALIAS')
            target=_name(posixpath.normpath(posixpath.join(posixpath.dirname(name),item.linkname)))
            require(_selected(target),'PUBLIC_TAR_ALIAS');aliases[name]=target
        if selected and item.isfile():
            selected_size+=item.size;require(selected_size<=MAX_CPU_BYTES,'PUBLIC_CPU_LIMIT')
            content=read(item.size);require(len(content)==item.size,'PUBLIC_TAR_TRUNCATED');files[name]=content
        else:
            size=item.size
            while size:
                block=read(min(BLOCK,size));require(block,'PUBLIC_TAR_TRUNCATED');size-=len(block)
        padding=(-item.size)%512
        require(len(read(padding))==padding,'PUBLIC_TAR_TRUNCATED')
    for name in kinds:
        remaining(deadline)
        parts=name.split('/')
        for depth in range(1,len(parts)):
            parent='/'.join(parts[:depth])
            require(parent not in kinds or kinds[parent]==tarfile.DIRTYPE,'PUBLIC_TAR_COLLISION')
    for name in aliases:
        remaining(deadline)
        seen=set();target=name
        while target in aliases:
            remaining(deadline)
            require(target not in seen,'PUBLIC_TAR_ALIAS');seen.add(target);target=aliases[target]
        require(target in files,'PUBLIC_TAR_ALIAS')
        selected_size+=len(files[target]);require(selected_size<=MAX_CPU_BYTES,'PUBLIC_CPU_LIMIT')
        files[name]=files[target]
    require({'bin/ollama','lib/ollama/llama-server','lib/ollama/libllama-server-impl.so',
             'lib/ollama/libllama-common.so'} <= files.keys(),'PUBLIC_CPU_INCOMPLETE')
    remaining(deadline)
    return files


class _Pipe:
    def __init__(self,stream,deadline):self.stream=stream;self.deadline=deadline
    def read(self,size):
        with selectors.DefaultSelector() as selector:
            selector.register(self.stream,selectors.EVENT_READ)
            require(selector.select(remaining(self.deadline)),'PUBLIC_RUNTIME_DEADLINE')
        return os.read(self.stream.fileno(),size)


def stage_cpu(archive,destination,deadline):
    verify_file(archive,OLLAMA_SIZE,OLLAMA_SHA,deadline)  # before any parsing
    with archive.open('rb') as stream:
        process=subprocess.Popen(['zstd','-dc'],stdin=stream,stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL,env={'PATH':os.defpath},bufsize=0)
        try:
            files=cpu_files(_Pipe(process.stdout,deadline),deadline)
            require(process.wait(timeout=remaining(deadline,5))==0,'PUBLIC_TAR_DECODE_FAILED')
        finally:
            if process.poll() is None:process.kill()
            process.wait(timeout=5);process.stdout.close()
    remaining(deadline);destination.mkdir(mode=0o755)
    hashes={}
    for name,content in files.items():
        remaining(deadline)
        output=destination/name;output.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        digest=hashlib.sha256()
        with output.open('xb') as stream:
            for offset in range(0,len(content),BLOCK):
                remaining(deadline);block=content[offset:offset+BLOCK]
                stream.write(block);digest.update(block);remaining(deadline)
        output.chmod(0o555)
        hashes[name]=digest.hexdigest();remaining(deadline)
    return hashes


if __name__=='__main__':
    try:
        require(len(sys.argv)==6 and sys.argv[1]=='download','PUBLIC_ASSET_ARGUMENTS')
        _download(sys.argv[2],pathlib.Path(sys.argv[3]),int(sys.argv[4]),sys.argv[5])
    except BaseException:raise SystemExit(2)
