"""Public supply-chain fixtures only. No model/binary execution."""
import base64
import io
import pathlib
import json
import hashlib
import os
import subprocess
import ssl
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import runtime_assets as assets
from data_driver import GateError

MANIFEST=base64.b64decode('eyJzY2hlbWFWZXJzaW9uIjoyLCJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmRpc3RyaWJ1dGlvbi5tYW5pZmVzdC52Mitqc29uIiwiY29uZmlnIjp7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuY29udGFpbmVyLmltYWdlLnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NTE3Y2NhZmYwMmZlOWY5OTcxOGFiMmY0NzhlNjExYWEyODEzYzM2MjYzZWVlZDg2YzI0MjdiYzEyMmQxNGFkOCIsInNpemUiOjQ4N30sImxheWVycyI6W3sibWVkaWFUeXBlIjoiYXBwbGljYXRpb24vdm5kLm9sbGFtYS5pbWFnZS5tb2RlbCIsImRpZ2VzdCI6InNoYTI1NjozZDBiNzkwNTM0ZmU0Yjc5NTI1ZmMzNjkyOTUwNDA4ZGNhNDExNzE2NzZlZDdlMjFkYjU3YWY1YzY1ZWY2YWI2Iiwic2l6ZSI6MTM1OTI3OTc3Nn0seyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2xsYW1hLmltYWdlLnRlbXBsYXRlIiwiZGlnZXN0Ijoic2hhMjU2OmFlMzcwZDg4NGYxMDhkMTZlN2NjOGZkNTI1OWViYzU3NzNhMGFmYTZlMDc4YjExZjRlZDdlMzlhMjdlMGRmYzQiLCJzaXplIjoxNzIzfSx7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5vbGxhbWEuaW1hZ2UubGljZW5zZSIsImRpZ2VzdCI6InNoYTI1NjpkMThhNWNjNzFiODRiYzRhZjM5NGEzMTExNmJkMzkzMmI0MjI0MWRlNzBjNzdkMmI3NmQ2OWEzMTRlYzhhYTEyIiwic2l6ZSI6MTEzMzh9LHsibWVkaWFUeXBlIjoiYXBwbGljYXRpb24vdm5kLm9sbGFtYS5pbWFnZS5wYXJhbXMiLCJkaWdlc3QiOiJzaGEyNTY6Y2ZmM2YzOTVlZjM3NTZhYjYzZTU4YjBhZDFiMzJiYjZmODAyOTA1Y2FlMTQ3MmU2YTEyMDM0ZTQyNDZmYmJkYiIsInNpemUiOjEyMH1dfQ==')


def tar_bytes(extras=(),omit=()):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name in ('bin/ollama','lib/ollama/llama-server','lib/ollama/libggml-base.so.0',
                     'lib/ollama/libllama-server-impl.so','lib/ollama/libllama-common.so'):
            if name in omit:continue
            item=tarfile.TarInfo(name);item.size=6
            archive.addfile(item,io.BytesIO(b'PUBLIC'))
        alias=tarfile.TarInfo('lib/ollama/libggml-base.so')
        alias.type=tarfile.SYMTYPE;alias.linkname='libggml-base.so.0';archive.addfile(alias)
        for item in extras:archive.addfile(item,io.BytesIO(b'x'*item.size) if item.isfile() else None)
    return stream.getvalue()


class RuntimeAssetsTest(unittest.TestCase):
    def test_all_proxy_only_has_https_fallback_and_keeps_no_proxy_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            for number,name in enumerate(('ALL_PROXY','all_proxy')):
                seen=[]
                def opener(*handlers):
                    seen.extend(handlers)
                    return type('PublicResponse',(),{'open':lambda self,*a,**kw:io.BytesIO(b'PUBLIC')})()
                env={name:'http://public-proxy.example:8123','NO_PROXY':'registry.ollama.ai'}
                with patch.dict(os.environ,env,clear=True),patch.object(assets.urllib.request,'build_opener',opener):
                    assets._download(assets.MANIFEST_URL,pathlib.Path(directory)/str(number),6,hashlib.sha256(b'PUBLIC').hexdigest())
                    proxy=next(h for h in seen if isinstance(h,assets.urllib.request.ProxyHandler))
                    self.assertTrue(callable(getattr(proxy,'https_open',None)),'ALL_PROXY silently bypasses HTTPS')
                    request=assets.urllib.request.Request(assets.MANIFEST_URL)
                    proxy.https_open(request)
                    self.assertEqual(request.host,'registry.ollama.ai')
                    with patch.dict(os.environ,{'NO_PROXY':''}):
                        request=assets.urllib.request.Request(assets.MANIFEST_URL)
                        proxy.https_open(request)
                        self.assertEqual(request.host,'public-proxy.example:8123')
                    self.assertEqual(os.environ[name],env[name])
                    self.assertNotIn('HTTPS_PROXY',os.environ)

    def test_unsupported_all_proxy_cannot_silently_use_direct_https(self):
        response=type('PublicResponse',(),{'open':lambda self,*a,**kw:io.BytesIO(b'PUBLIC')})()
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'ALL_PROXY':'socks5://public-proxy.example:1080'},clear=True), \
             patch.object(assets.urllib.request,'build_opener',return_value=response):
            with self.assertRaisesRegex(GateError,'^PUBLIC_ASSET_PROXY_UNSUPPORTED$'):
                assets._download(assets.MANIFEST_URL,pathlib.Path(directory)/'unused',6,hashlib.sha256(b'PUBLIC').hexdigest())

    def test_public_download_preserves_only_the_explicit_transport_environment(self):
        transport = {name:'PUBLIC-TRANSPORT-'+name for name in
            ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy',
             'all_proxy','no_proxy','SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE')}
        environment = dict(transport, AI09_BUNDLE_KEY_B64='PUBLIC-KEY-CANARY',
            GITHUB_TOKEN='PUBLIC-TOKEN-CANARY', GITHUB_OUTPUT='PUBLIC-COMMAND-CANARY',
            UNRELATED='PUBLIC-UNRELATED-CANARY', SYSTEMROOT='PUBLIC-WINDOWS-RUNTIME')
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'public'
            def run(argv,**kwargs):
                observed.append(kwargs['env'])
                output.write_bytes(b'PUBLIC')
                return subprocess.CompletedProcess(argv,0)
            with patch.dict(os.environ,environment,clear=True), patch.object(assets.subprocess,'run',run):
                assets.download(assets.MANIFEST_URL,output,6,hashlib.sha256(b'PUBLIC').hexdigest(),time.monotonic()+5)
        self.assertEqual(len(observed),1)
        for name,value in transport.items(): self.assertEqual(observed[0].get(name),value)
        for name in ('AI09_BUNDLE_KEY_B64','GITHUB_TOKEN','GITHUB_OUTPUT','UNRELATED'):
            self.assertNotIn(name,observed[0])
        self.assertEqual(observed[0]['PATH'],os.defpath)

    def test_download_uses_inherited_proxy_and_verified_configured_ca_precedence(self):
        # A generated test file containing a public CA certificate, never a key.
        certificates=ssl.create_default_context().get_ca_certs(binary_form=True)
        self.assertTrue(certificates)
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory); ca=base/'public-ca.pem'
            ca.write_text(ssl.DER_cert_to_PEM_cert(certificates[0]))
            variants=({'SSL_CERT_FILE':str(ca),'REQUESTS_CA_BUNDLE':'missing-requests','CURL_CA_BUNDLE':'missing-curl'},
                      {'SSL_CERT_DIR':str(base),'REQUESTS_CA_BUNDLE':'missing-requests'},
                      {'REQUESTS_CA_BUNDLE':str(ca),'CURL_CA_BUNDLE':'missing-curl'},
                      {'CURL_CA_BUNDLE':str(ca)})
            for number,ca_environment in enumerate(variants):
                seen=[]
                def opener(*handlers):
                    seen.extend(handlers)
                    return type('PublicResponse',(),{'open':lambda self,*a,**kw:io.BytesIO(b'PUBLIC')})()
                env=dict(ca_environment,HTTPS_PROXY='http://public-proxy.example:8123',NO_PROXY='localhost')
                with self.subTest(case=number),patch.dict(os.environ,env,clear=True),\
                     patch.object(assets.urllib.request,'build_opener',opener):
                    assets._download(assets.MANIFEST_URL,base/str(number),6,hashlib.sha256(b'PUBLIC').hexdigest())
                proxies=[h for h in seen if isinstance(h,assets.urllib.request.ProxyHandler)]
                self.assertEqual(proxies[0].proxies.get('https'),'http://public-proxy.example:8123')
                tls=[h for h in seen if isinstance(h,assets.urllib.request.HTTPSHandler)]
                self.assertEqual(len(tls),1,'configured verified TLS handler is missing')
                self.assertTrue(tls[0]._context.check_hostname)
                self.assertEqual(tls[0]._context.verify_mode,ssl.CERT_REQUIRED)

    def test_download_verification_cannot_return_success_after_deadline(self):
        class Slow(io.BytesIO):
            def read(self,size=-1):
                time.sleep(0.04)
                return super().read(size)
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'public';output.write_bytes(b'PUBLIC')
            with patch.object(assets.subprocess,'run',return_value=subprocess.CompletedProcess([],0)),patch.object(pathlib.Path,'open',lambda *a,**kw:Slow(b'PUBLIC')):
                with self.assertRaisesRegex(GateError,'^PUBLIC_RUNTIME_DEADLINE$'):
                    assets.download(assets.MANIFEST_URL,output,6,hashlib.sha256(b'PUBLIC').hexdigest(),time.monotonic()+0.02)
    def test_download_child_has_runtime_environment_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'public'
            def run(argv,**kwargs):
                self.assertNotIn('AI09_BUNDLE_KEY_B64',kwargs['env'])
                self.assertNotIn('PRIVATE-CANARY',str(kwargs['env']))
                if os.name=='nt':self.assertIn('SYSTEMROOT',kwargs['env'])
                output.write_bytes(b'PUBLIC')
                return subprocess.CompletedProcess(argv,0)
            with patch.dict(os.environ,{'AI09_BUNDLE_KEY_B64':'PRIVATE-CANARY'}),patch.object(assets.subprocess,'run',run):
                assets.download(assets.MANIFEST_URL,output,6,hashlib.sha256(b'PUBLIC').hexdigest(),time.monotonic()+5)
    def test_model_manifest_pins_all_five_blobs(self):
        entries=assets.model_blobs(MANIFEST)
        self.assertEqual(len(entries),5)
        self.assertEqual(sum(size for _,size in entries),1359293444)
        for raw in (MANIFEST+b' ',MANIFEST.replace(b'1359279776',b'1359279777')):
            with self.assertRaises(GateError):assets.model_blobs(raw)

    def test_download_url_policy_rejects_other_hosts_http_and_arbitrary_paths(self):
        self.assertTrue(assets.allowed_url(assets.OLLAMA_URL))
        self.assertTrue(assets.allowed_url(assets.MANIFEST_URL))
        for url in ('http://registry.ollama.ai/a','https://example.com/model',
                    'https://registry.ollama.ai.evil.test/a','https://127.0.0.1/a',
                    'https://github.com/other/repo/releases/download/a/b'):
            self.assertFalse(assets.allowed_url(url))

    def test_cpu_selection_copies_safe_aliases_without_host_symlinks(self):
        files=assets.cpu_files(io.BytesIO(tar_bytes()),time.monotonic()+5)
        self.assertEqual(files['lib/ollama/libggml-base.so'],b'PUBLIC')
        self.assertEqual(set(files),{'bin/ollama','lib/ollama/llama-server',
                                    'lib/ollama/libggml-base.so.0','lib/ollama/libggml-base.so',
                                    'lib/ollama/libllama-server-impl.so','lib/ollama/libllama-common.so'})
    def test_gpu_or_mlx_root_files_are_not_selected_as_cpu(self):
        extras=[]
        for name in ('lib/ollama/ollama-mlx-cuda','lib/ollama/libggml-cuda.so'):
            item=tarfile.TarInfo(name);item.size=6;extras.append(item)
        files=assets.cpu_files(io.BytesIO(tar_bytes(extras)),time.monotonic()+5)
        self.assertNotIn('lib/ollama/ollama-mlx-cuda',files)
        self.assertNotIn('lib/ollama/libggml-cuda.so',files)

    def test_cpu_server_shared_implementation_and_common_dependencies_are_retained(self):
        # Ollama v0.34.0's shared CPU build links these two libraries.
        names=('lib/ollama/libllama-server-impl.so','lib/ollama/libllama-common.so')
        files=assets.cpu_files(io.BytesIO(tar_bytes()),time.monotonic()+5)
        for name in names:
            self.assertEqual(files[name],b'PUBLIC')
            with self.assertRaisesRegex(GateError,'^PUBLIC_CPU_INCOMPLETE$'):
                assets.cpu_files(io.BytesIO(tar_bytes(omit=(name,))),time.monotonic()+5)
        self.assertFalse(assets._selected('lib/ollama/libllama-quantize-impl.so'))

    def test_tar_unsafe_paths_links_special_records_and_duplicates_are_rejected(self):
        variants=[]
        for name in ('../PRIVATE','/absolute','bin/ollama'):
            variants.append(tarfile.TarInfo(name))
        for kind in (tarfile.XHDTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_SPARSE,tarfile.LNKTYPE,tarfile.CHRTYPE):
            item=tarfile.TarInfo('unsafe');item.type=kind;variants.append(item)
        link=tarfile.TarInfo('lib/ollama/libggml-base.so.escape');link.type=tarfile.SYMTYPE;link.linkname='../../../etc/passwd';variants.append(link)
        for item in variants:
            with self.subTest(name=item.name,kind=item.type):
                with self.assertRaises(GateError):assets.cpu_files(io.BytesIO(tar_bytes([item])),time.monotonic()+5)

    def test_selected_total_and_overall_deadline_are_enforced(self):
        with patch.object(assets,'MAX_CPU_BYTES',5):
            with self.assertRaises(GateError):assets.cpu_files(io.BytesIO(tar_bytes()),time.monotonic()+5)
        with self.assertRaises(GateError):assets.cpu_files(io.BytesIO(tar_bytes()),time.monotonic()-1)

    def test_pax_header_is_rejected_without_reading_declared_payload(self):
        item=tarfile.TarInfo('metadata');item.type=tarfile.XHDTYPE;item.size=2_000_000_000
        raw=item.tobuf(format=tarfile.USTAR_FORMAT)
        with self.assertRaises(GateError):assets.cpu_files(io.BytesIO(raw),time.monotonic()+5)

    def test_inventory_version_name_and_digest_must_match_pins(self):
        version=b'{"version":"0.34.0"}'
        tags={'models':[{'name':'qwen3:1.7b','digest':assets.MODEL_SHA}]}
        assets.validate_inventory(version,json.dumps(tags).encode())
        for changed in ({'models':[]},{'models':[{'name':'other','digest':assets.MODEL_SHA}]},
                        {'models':[{'name':'qwen3:1.7b','digest':'a'*64}]}):
            with self.assertRaises(GateError):assets.validate_inventory(version,json.dumps(changed).encode())
        with self.assertRaises(GateError):assets.validate_inventory(b'{"version":"other"}',json.dumps(tags).encode())


if __name__=='__main__':unittest.main()
