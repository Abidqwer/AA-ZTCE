"""Attach fail-closed assurance profiles to the existing runtime engine."""
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from .etcd import Etcd,Revocations,install
from .tpm import TPM
from .transport import HTTPS,canonical
from .witness import WitnessClient


def attach(domain,config,journal=None):
    if set(config)-{'domain_id','node_id','tpm','witness','consensus','consensus_control','attest_every_operation'}:
        raise ValueError('unknown assurance configuration')
    domain_id=config['domain_id'];node_id=config['node_id']
    tpm=TPM(**config['tpm']) if config.get('tpm') else None
    witness=None
    if config.get('witness'):
        if journal is None or tpm is None:raise ValueError('strict witnessing requires a journal and TPM signer')
        settings=dict(config['witness']);public=settings.pop('receipt_public_file')
        witness=WitnessClient(HTTPS(**settings),domain_id,node_id,public)
        # Synchronize existing records with the external head before serving requests.
        witness.anchor(journal,tpm)
        journal.anchor_callback=lambda current:witness.anchor(current,tpm)
        public_hash=hashlib.sha256(domain.verifier.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        def attest(context):return witness.attest(tpm,{'gateway_public_sha256':public_hash,**context})
        previous=domain.admission_authority
        def admission(request):
            attest({'phase':'admission','principal':request['agent'],'request_sha256':hashlib.sha256(canonical(request)).hexdigest()})
            return previous(request)
        domain.admission_authority=admission
        if config.get('attest_every_operation',True):
            prior=domain.operation_authority
            def operation(body,grant):
                attest({'phase':'operation','principal':grant['agent'],'session_id':grant['sid'],
                    'request_sha256':hashlib.sha256(canonical(body)).hexdigest()})
                return prior(body,grant)
            domain.operation_authority=operation
    elif tpm:raise ValueError('TPM assurance requires an independently configured witness/verifier')
    if config.get('consensus'):
        reader=Etcd(**config['consensus'])
        controller=Etcd(**config['consensus_control']) if config.get('consensus_control') else None
        revocations=Revocations(reader,domain_id,node_id,controller)
        # Verify the control-plane path is reachable at startup. A missing key is valid.
        reader.range(revocations.key('agent','@startup'))
        install(domain,revocations)
    if not witness and not config.get('consensus'):raise ValueError('empty assurance profile')
    return {'tpm':tpm,'witness':witness,'distributed':getattr(domain,'distributed',None)}
