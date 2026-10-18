"""Generate working local TLS and client credentials; no embedded example secrets."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import secrets
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def initialize(directory):
    root=Path(directory).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700);root.chmod(0o700)
    if (root/'soc-config.json').exists():return json.loads((root/'soc-config.json').read_text())
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'AA-ZTCE local integration')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
        .not_valid_after(now+datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                       x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
        .sign(key,hashes.SHA256()))
    certfile=root/'local-cert.pem';keyfile=root/'local-key.pem';secretfile=root/'operator.key'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    secretfile.write_text(secrets.token_hex(32)+'\n')
    for p in (keyfile,secretfile):p.chmod(0o600)
    config={'state_dir':str(root),'domain_id':'Domain-X','max_events':100000,'siem_sinks':[],
        'soar':{'host':'127.0.0.1','port':0,'cert_file':str(certfile),'key_file':str(keyfile),'client_ca':str(certfile),
                'clients':[{'id':'soc-operator','key_file':str(secretfile),
                    'actions':['read_events','revoke_session','suspend_session','require_reauth','disable_agent'],
                    'agents':['A','B','C','D']}]}}
    path=root/'soc-config.json';path.write_text(json.dumps(config,indent=2));path.chmod(0o600)
    return config
