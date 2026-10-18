"""Isolated synthetic PKI, TPM and three-node etcd fixtures. Never production PKI."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from .etcd import Etcd,b64


def port():
    s=socket.socket();s.bind(('127.0.0.1',0));value=s.getsockname()[1];s.close();return value


def pki(root):
    import ipaddress
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'AA-ZTCE synthetic assurance test CA')])
    now=datetime.datetime.now(datetime.timezone.utc)
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()))
    (root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM));result={'ca':str(root/'ca.pem')}
    for label in ('service','peer0','peer1','peer2','node0','node1','node2','controller'):
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,label)]) if label.startswith('node') or label=='controller' else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label)]))
            .issuer_name(name).public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),False)
            .sign(key,hashes.SHA256()))
        public=root/(label+'.pem');secret=root/(label+'-key.pem')
        public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        secret.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));secret.chmod(0o600)
        result[label]={'cert':str(public),'key':str(secret),'fingerprint':cert.fingerprint(hashes.SHA256()).hex()}
    receipt=ed25519.Ed25519PrivateKey.generate()
    secret=root/'receipt-key.pem';secret.write_bytes(receipt.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));secret.chmod(0o600)
    public=root/'receipt-public.pem';public.write_bytes(receipt.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    result.update(receipt_key=str(secret),receipt_public=str(public));return result


class Cluster:
    def __init__(self,root,certificates,executable,domain='Domain-X'):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.pki=certificates;self.executable=executable
        self.ports=[(port(),port()) for _ in range(3)];self.processes=[None]*3;self.logs=[];self.domain=domain
        self.endpoints=['https://127.0.0.1:'+str(p[0]) for p in self.ports]
        for i in range(3):self.start(i)
        config={'endpoints':self.endpoints,'ca_file':certificates['ca'],'cert_file':certificates['controller']['cert'],
            'key_file':certificates['controller']['key'],'timeout':.6,'allow_no_rbac':True}
        initial=Etcd(**config)
        deadline=time.monotonic()+15
        while True:
            try:initial.range('/ready');break
            except Exception:
                if time.monotonic()>deadline:raise RuntimeError('three-node etcd startup failed')
                time.sleep(.1)
        password=secrets.token_urlsafe(24);root_pw=self.root/'controller.password';root_pw.write_text(password);root_pw.chmod(0o600)
        initial.call('/v3/auth/user/add',{'name':'root','password':password})
        initial.call('/v3/auth/user/grant',{'user':'root','role':'root'})
        for i in range(3):
            username='node'+str(i);pw=secrets.token_urlsafe(24);path=self.root/(username+'.password');path.write_text(pw);path.chmod(0o600)
            initial.call('/v3/auth/user/add',{'name':username,'password':pw})
            initial.call('/v3/auth/role/add',{'name':username})
            # Read-only revocation state; write only this node's decision watermark.
            prefix='/aa-ztce/v1/'+domain+'/'
            for suffix in ('agent/','session/'):
                start=prefix+suffix;end=start[:-1]+chr(ord(start[-1])+1)
                initial.call('/v3/auth/role/grant',{'name':username,'perm':{'permType':'READ','key':b64(start),'range_end':b64(end)}})
            decision=prefix+'last_authorized/'+b64(username).replace('/','_').replace('+','-')
            initial.call('/v3/auth/role/grant',{'name':username,'perm':{'permType':'READWRITE','key':b64(decision)}})
            initial.call('/v3/auth/user/grant',{'user':username,'role':username})
        initial.call('/v3/auth/enable',{})
        self.config={**config,'allow_no_rbac':False,'username':'root','password_file':str(root_pw)}
        self.controller=Etcd(**self.config)
    def config_for(self,i):
        return {**self.config,'username':'node'+str(i),'password_file':str(self.root/('node'+str(i)+'.password')),
            'cert_file':self.pki['node'+str(i)]['cert'],'key_file':self.pki['node'+str(i)]['key']}
    def start(self,i):
        cert=self.pki['peer'+str(i)];cp,pp=self.ports[i]
        log=(self.root/('etcd'+str(i)+'.log')).open('ab');self.logs.append(log)
        cluster=','.join('n'+str(j)+'=https://127.0.0.1:'+str(p[1]) for j,p in enumerate(self.ports))
        args=[self.executable,'--name','n'+str(i),'--data-dir',str(self.root/('data'+str(i))),
            '--listen-client-urls','https://127.0.0.1:'+str(cp),'--advertise-client-urls','https://127.0.0.1:'+str(cp),
            '--listen-peer-urls','https://127.0.0.1:'+str(pp),'--initial-advertise-peer-urls','https://127.0.0.1:'+str(pp),
            '--initial-cluster',cluster,'--initial-cluster-token','aa-ztce-test','--initial-cluster-state','new',
            '--cert-file',cert['cert'],'--key-file',cert['key'],'--trusted-ca-file',self.pki['ca'],'--client-cert-auth',
            '--peer-cert-file',cert['cert'],'--peer-key-file',cert['key'],'--peer-trusted-ca-file',self.pki['ca'],
            '--peer-client-cert-auth','--logger','zap','--log-level','error']
        self.processes[i]=subprocess.Popen(args,stdout=log,stderr=log,close_fds=True)
    def stop(self,i):
        p=self.processes[i]
        if p and p.poll() is None:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    def leader(self):
        status=self.controller.call('/v3/maintenance/status',{})
        leader=str(status['leader'])
        for i,url in enumerate(self.endpoints):
            client=Etcd(**{**self.config,'endpoints':[url]})
            value=client.call('/v3/maintenance/status',{})
            if str(value['header']['member_id'])==leader:return i
        raise RuntimeError('leader not found')
    def close(self):
        for i in range(3):self.stop(i)
        for log in self.logs:log.close()
