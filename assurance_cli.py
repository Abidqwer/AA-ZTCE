#!/usr/bin/env python3
"""Ready CLI for provisioning, witness enrollment, profile creation and revocation."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import threading
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from enterprise.keys import generate_pkcs11_key,PKCS11Ed25519
from assurance.tpm import provision
from assurance.etcd import Etcd,Revocations
from assurance.witness import Witness


def save(path,value):
    p=Path(path).resolve();p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    p.write_text(json.dumps(value,indent=2)+'\n');p.chmod(0o600);return p

def tls_arguments(parser,prefix=''):
    for name in ('ca','cert','key'):parser.add_argument('--'+prefix+name,required=True)

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    t=sub.add_parser('provision-tpm');t.add_argument('--directory',required=True);t.add_argument('--tcti',default='device:/dev/tpmrm0');t.add_argument('--auth-file',required=True);t.add_argument('--tools-dir',default='');t.add_argument('--isolated-emulator',action='store_true');t.add_argument('--owner-auth-file')
    for kind,default in [('parent','0x8101a001'),('audit','0x8101a002'),('attestation','0x8101a003')]:t.add_argument('--'+kind+'-handle',default=default)
    quote=sub.add_parser('quote-tpm');quote.add_argument('--config',required=True);quote.add_argument('--qualifying-hex',required=True);quote.add_argument('--directory',required=True)
    h=sub.add_parser('keygen-hsm');h.add_argument('--module',required=True);h.add_argument('--token',required=True);h.add_argument('--label',required=True);h.add_argument('--pin-file',required=True);h.add_argument('--public-output',required=True);h.add_argument('--profile-output',required=True);h.add_argument('--allow-software-token',action='store_true')
    w=sub.add_parser('init-witness');w.add_argument('--directory',required=True);tls_arguments(w);w.add_argument('--host',default='127.0.0.1');w.add_argument('--port',type=int,default=9443);w.add_argument('--tools-dir',default='')
    e=sub.add_parser('enroll-witness');e.add_argument('--config',required=True);e.add_argument('--domain',required=True);e.add_argument('--node',required=True)
    for flag in ('audit-public','audit-key-id','attestation-public','approved-pcr-file','gateway-public','client-cert'):e.add_argument('--'+flag,required=True)
    e.add_argument('--algorithm',choices=['ECDSA-P256-SHA256','Ed25519'],default='ECDSA-P256-SHA256')
    serve=sub.add_parser('serve-witness');serve.add_argument('--config',required=True)
    profile=sub.add_parser('make-profile');profile.add_argument('--output',required=True);profile.add_argument('--domain',required=True);profile.add_argument('--node',required=True);profile.add_argument('--tpm-config',required=True)
    profile.add_argument('--witness-url',required=True);profile.add_argument('--receipt-public',required=True);tls_arguments(profile,'witness-')
    profile.add_argument('--etcd-endpoints',nargs='+',required=True);tls_arguments(profile,'etcd-');profile.add_argument('--etcd-username',required=True);profile.add_argument('--etcd-password-file',required=True)
    profile.add_argument('--control-profile');profile.add_argument('--attest-at-admission-only',action='store_true')
    attach=sub.add_parser('attach');attach.add_argument('--gateway-config',required=True);attach.add_argument('--profile',required=True);attach.add_argument('--signing-profile',required=True)
    revoke=sub.add_parser('revoke');revoke.add_argument('--profile',required=True);revoke.add_argument('--agent',required=True);revoke.add_argument('--action',choices=['revoke_session','suspend_session','require_reauth','disable_agent','enable_agent'],required=True);revoke.add_argument('--session');revoke.add_argument('--command-id')
    a=p.parse_args()
    if a.command=='provision-tpm':
        cfg=provision(a.tcti,a.directory,a.auth_file,tools_dir=a.tools_dir,isolated_emulator=a.isolated_emulator,
            parent_handle=a.parent_handle,audit_handle=a.audit_handle,attestation_handle=a.attestation_handle,owner_auth_file=a.owner_auth_file)
        print(json.dumps({'config':str(Path(a.directory).resolve()/'tpm-config.json'),'key_id':cfg['key_id']}))
    elif a.command=='quote-tpm':
        from assurance.tpm import TPM,unb64
        evidence=TPM(**json.loads(Path(a.config).read_text())).quote(a.qualifying_hex)
        root=Path(a.directory).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
        for name,value in evidence.items():(root/(name+'.bin')).write_bytes(unb64(value))
        save(root/'evidence.json',evidence);print(json.dumps({'evidence':str(root/'evidence.json'),'pcr_reference_candidate':str(root/'pcrs.bin'),'note':'Accept a reference only through an independent known-good enrollment process.'}))
    elif a.command=='keygen-hsm':
        import pkcs11
        token=pkcs11.lib(a.module).get_token(token_label=a.token)
        if not a.allow_software_token and not token.slot.flags & pkcs11.SlotFlag.HW_SLOT:raise ValueError('hardware slot required')
        generate_pkcs11_key(a.module,a.token,a.label,a.pin_file)
        key=PKCS11Ed25519(a.module,a.token,a.label,a.pin_file,allow_software_token=a.allow_software_token)
        Path(a.public_output).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        save(a.profile_output,{'type':'pkcs11_ed25519','module':str(Path(a.module).resolve()),'token_label':a.token,'key_label':a.label,
            'pin_file':str(Path(a.pin_file).resolve()),'allow_software_token':a.allow_software_token})
        print(json.dumps({'public_key':str(Path(a.public_output).resolve()),'signing_profile':str(Path(a.profile_output).resolve())}))
    elif a.command=='init-witness':
        root=Path(a.directory).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
        if (root/'witness.json').exists() or (root/'receipt-key.pem').exists():raise ValueError('existing witness not overwritten')
        key=ed25519.Ed25519PrivateKey.generate();secret=root/'receipt-key.pem';secret.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));secret.chmod(0o600)
        (root/'receipt-public.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        save(root/'witness.json',{'database':str(root/'witness.sqlite'),'receipt_key_file':str(secret),
            'cert_file':str(Path(a.cert).resolve()),'key_file':str(Path(a.key).resolve()),'client_ca':str(Path(a.ca).resolve()),
            'host':a.host,'port':a.port,'nodes':{},'tools_dir':a.tools_dir})
        print(json.dumps({'config':str(root/'witness.json'),'receipt_public':str(root/'receipt-public.pem')}))
    elif a.command=='enroll-witness':
        config=json.loads(Path(a.config).read_text());target=a.domain+'/'+a.node
        if target in config['nodes']:raise ValueError('existing node enrollment not overwritten')
        public=serialization.load_pem_public_key(Path(a.gateway_public).read_bytes())
        config['nodes'][target]={'audit_public_file':str(Path(a.audit_public).resolve()),'audit_key_id':a.audit_key_id,
            'algorithm':a.algorithm,'attestation_public_file':str(Path(a.attestation_public).resolve()),
            'approved_pcr_sha256':hashlib.sha256(Path(a.approved_pcr_file).read_bytes()).hexdigest(),
            'gateway_public_sha256':hashlib.sha256(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
            'client_fingerprints':[x509.load_pem_x509_certificate(Path(a.client_cert).read_bytes()).fingerprint(hashes.SHA256()).hex()]}
        save(a.config,config);print(json.dumps({'enrolled':target,'restart_witness_required':True}))
    elif a.command=='serve-witness':
        witness=Witness(json.loads(Path(a.config).read_text()));stop=threading.Event()
        signal.signal(signal.SIGTERM,lambda *x:stop.set());signal.signal(signal.SIGINT,lambda *x:stop.set())
        witness.start();print(json.dumps({'url':witness.url,'status':'ready'}),flush=True)
        try:stop.wait()
        finally:witness.close()
    elif a.command=='make-profile':
        config={'domain_id':a.domain,'node_id':a.node,'tpm':json.loads(Path(a.tpm_config).read_text()),
            'witness':{'url':a.witness_url,'ca_file':str(Path(a.witness_ca).resolve()),'cert_file':str(Path(a.witness_cert).resolve()),
                'key_file':str(Path(a.witness_key).resolve()),'receipt_public_file':str(Path(a.receipt_public).resolve())},
            'consensus':{'endpoints':a.etcd_endpoints,'ca_file':str(Path(a.etcd_ca).resolve()),'cert_file':str(Path(a.etcd_cert).resolve()),
                'key_file':str(Path(a.etcd_key).resolve()),'username':a.etcd_username,'password_file':str(Path(a.etcd_password_file).resolve())},
            'attest_every_operation':not a.attest_at_admission_only}
        if a.control_profile:config['consensus_control']=json.loads(Path(a.control_profile).read_text())
        print(json.dumps({'profile':str(save(a.output,config))}))
    elif a.command=='attach':
        config=json.loads(Path(a.gateway_config).read_text());config['assurance']=json.loads(Path(a.profile).read_text());config['signing']=json.loads(Path(a.signing_profile).read_text())
        if not config.get('soc'):raise ValueError('SOC journal must be configured before strict assurance attach')
        save(a.gateway_config,config);print(json.dumps({'attached':True,'restart_required':True}))
    else:
        config=json.loads(Path(a.profile).read_text());control=config.get('consensus_control')
        if not control:raise ValueError('external control profile required')
        backend=Revocations(Etcd(**control),config['domain_id'],config['node_id'],Etcd(**control))
        if a.action.endswith('_session'):
            if not a.session:p.error('--session required')
            revision=backend.change_session(a.session,a.agent,'REVOKED' if a.action=='revoke_session' else 'PENDING')
            result={'status':'committed','revision':revision}
        else:
            enabled=None if a.action=='require_reauth' else a.action=='enable_agent'
            result={'status':'committed','epoch':backend.change_agent(a.agent,enabled,a.command_id)}
        print(json.dumps(result))

if __name__=='__main__':main()
