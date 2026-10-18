"""Install a local-only lab runtime; no services, TPM resets or global apt edits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]


def run(args,log,env=None):
    with log.open('ab') as stream:
        result=subprocess.run(args,stdout=stream,stderr=stream,env=env)
    if result.returncode:raise RuntimeError('Dependency setup failed; inspect '+str(log))


def fetch(url,path,expected):
    if path.is_file() and digest(path)==expected:return
    temporary=path.with_suffix(path.suffix+'.partial')
    with urllib.request.urlopen(url,timeout=60) as response,temporary.open('wb') as output:
        while block:=response.read(1048576):output.write(block)
    if digest(temporary)!=expected:
        temporary.unlink(missing_ok=True);raise RuntimeError('Download checksum mismatch: '+path.name)
    temporary.replace(path)


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1048576):h.update(block)
    return h.hexdigest()


def prepare(cache,with_model=True):
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64'):
        raise RuntimeError('This pinned installer supports Linux x86_64; use a Linux VM or WSL Ubuntu 24.04.')
    cache=Path(cache).resolve();cache.mkdir(parents=True,exist_ok=True)
    native=cache/'native';packages=cache/'packages';lists=cache/'lists'
    log=cache/'install.log';data=json.loads((ROOT/'range/downloads.json').read_text())
    tools=native/'usr/bin';module=native/'usr/lib/softhsm/libsofthsm2.so'
    if not all((tools/name).is_file() for name in ('swtpm','softhsm2-util','tpm2_sign','tpm2_quote','tpm2_checkquote')) or not module.exists() or not (native/'usr/lib/x86_64-linux-gnu/libgomp.so.1').exists():
        if not shutil.which('apt-get') or not shutil.which('dpkg-deb'):raise RuntimeError('Ubuntu/Debian apt-get and dpkg-deb are required')
        import pwd
        for folder in (native,packages,packages/'partial',lists,lists/'partial'):folder.mkdir(parents=True,exist_ok=True)
        options=['-o','Debug::NoLocking=true','-o','APT::Sandbox::User='+pwd.getpwuid(os.getuid()).pw_name,
            '-o','Dir::State::lists='+str(lists),'-o','Dir::Cache::archives='+str(packages)]
        print('Downloading signed-distribution TPM/SoftHSM packages into the local lab cache...',flush=True)
        run(['apt-get',*options,'update'],log)
        # --download-only + local extraction: no dpkg installation or maintainer scripts.
        run(['apt-get',*options,'--download-only','--reinstall','--no-install-recommends','-y','install',
            'swtpm','tpm2-tools','libtss2-tcti-swtpm0','softhsm2','libsofthsm2','libtpms0','softhsm2-common','libgomp1','libstdc++6','libseccomp2'],log)
        for package in sorted(packages.glob('*.deb')):run(['dpkg-deb','-x',str(package),str(native)],log)
    archive=cache/'etcd.tgz';fetch(data['etcd']['url'],archive,data['etcd']['sha256'])
    etcd=cache/'etcd-v3.6.5-linux-amd64/etcd'
    if not etcd.is_file():
        with tarfile.open(archive) as tar:tar.extractall(cache,filter='data')
    result={'AA_TPM_TOOLS_DIR':str(tools),'AA_SWTPM':str(tools/'swtpm'),'AA_SOFTHSM_UTIL':str(tools/'softhsm2-util'),
        'AA_PKCS11_MODULE':str(module),'AA_ETCD':str(etcd),
        'LD_LIBRARY_PATH':str(native/'usr/lib/x86_64-linux-gnu')+':'+str(native/'usr/lib/x86_64-linux-gnu/swtpm')+
            (':'+os.environ['LD_LIBRARY_PATH'] if os.environ.get('LD_LIBRARY_PATH') else '')}
    if with_model:
        print('Preparing checksum-pinned local Qwen model (491 MB) and llama.cpp CPU server...',flush=True)
        archive=cache/'llama.tgz';fetch(data['llama']['url'],archive,data['llama']['sha256'])
        server=cache/'llama-b11669/llama-server'
        if not server.is_file():
            with tarfile.open(archive) as tar:tar.extractall(cache,filter='data')
        model=cache/'qwen2.5-0.5b-instruct-q4_k_m.gguf';fetch(data['model']['url'],model,data['model']['sha256'])
        result.update(AA_RANGE_LLAMA=str(server),AA_RANGE_MODEL=str(model))
    (cache/'environment.json').write_text(json.dumps(result,indent=2)+'\n')
    # Package hashes are recorded as downloaded; apt authenticates repository metadata.
    (cache/'native-package-hashes.json').write_text(json.dumps({p.name:digest(p) for p in packages.glob('*.deb')},indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--cache',default=str(ROOT/'.assurance_cache'));p.add_argument('--no-model',action='store_true');a=p.parse_args()
    prepare(a.cache,not a.no_model)
