"""Software and PKCS#11 Ed25519 signing providers.

PKCS#11 is tested with SoftHSM; physical hardware protection is not established.
TPM audit signing and quote verification are implemented in assurance/tpm.py.
No PQC negotiation or hardware guarantee is implied by this interface.
"""
from typing import Protocol
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyProvider(Protocol):
    algorithm: str
    key_id: str
    def sign(self, message: bytes) -> bytes: ...
    def public_key(self): ...


class SoftwareEd25519:
    algorithm = 'Ed25519'
    def __init__(self, key=None, key_id='gateway-software'):
        self.key_id = key_id
        self._key = key or Ed25519PrivateKey.generate()
    def sign(self, message): return self._key.sign(message)
    def public_key(self): return self._key.public_key()


class PKCS11Ed25519:
    """Ed25519 signing inside a pre-enrolled PKCS#11 token; no key export/fallback.

    Hardware status is the module's reported slot capability, not attestation.
    Software tokens are accepted only through an explicit test-profile option.
    """
    algorithm = 'Ed25519'
    _locks = {}
    def __init__(self, module, token_label, key_label, pin_file, *, allow_software_token=False):
        import pkcs11
        import threading
        from pathlib import Path
        self.p11=pkcs11;self.module=pkcs11.lib(module)
        self.token=self.module.get_token(token_label=token_label)
        if not allow_software_token and not self.token.slot.flags & pkcs11.SlotFlag.HW_SLOT:
            raise ValueError('hardware PKCS#11 slot required; software-token profile must be explicit')
        self.pin=Path(pin_file).read_text().strip()
        if not self.pin:raise ValueError('empty token PIN')
        self.key_id=key_label;self.token_label=token_label
        self.lock=self._locks.setdefault((module,token_label),threading.RLock())
        with self.lock, self.token.open(user_pin=self.pin) as session:
            key=session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                                key_type=pkcs11.KeyType.EC_EDWARDS,label=key_label)
            if key[pkcs11.Attribute.EXTRACTABLE] or not key[pkcs11.Attribute.SENSITIVE]:
                raise ValueError('non-exportable sensitive key required')
            public=session.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                                    key_type=pkcs11.KeyType.EC_EDWARDS,label=key_label)
            from asn1crypto.core import OctetString
            point=public[pkcs11.Attribute.EC_POINT]
            try:point=OctetString.load(point).native
            except ValueError:pass
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            self._public=Ed25519PublicKey.from_public_bytes(point)
        # Prove the configured private and public key objects match.
        self._public.verify(self.sign(b'AA-ZTCE provider startup self-test'),b'AA-ZTCE provider startup self-test')
    def public_key(self):return self._public
    def sign(self,message):
        if type(message) is not bytes or len(message)>1048576:raise ValueError('invalid signing input')
        p=self.p11
        with self.lock, self.token.open(user_pin=self.pin) as session:
            key=session.get_key(object_class=p.ObjectClass.PRIVATE_KEY,key_type=p.KeyType.EC_EDWARDS,label=self.key_id)
            return bytes(key.sign(message,mechanism=p.Mechanism.EDDSA))


def generate_pkcs11_key(module,token_label,key_label,pin_file):
    """Explicit provisioning operation; existing labels are never overwritten."""
    import pkcs11 as p
    from pathlib import Path
    token=p.lib(module).get_token(token_label=token_label)
    with token.open(rw=True,user_pin=Path(pin_file).read_text().strip()) as session:
        if list(session.get_objects({p.Attribute.LABEL:key_label})):
            raise ValueError('key label already exists')
        session.generate_keypair(p.KeyType.EC_EDWARDS,store=True,label=key_label,
            mechanism=p.Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
            public_template={p.Attribute.EC_PARAMS:bytes.fromhex('06032b6570'),p.Attribute.VERIFY:True},
            private_template={p.Attribute.SENSITIVE:True,p.Attribute.EXTRACTABLE:False,p.Attribute.SIGN:True,p.Attribute.PRIVATE:True})


def provider_from_config(config):
    kind=config.get('type','software_ed25519')
    if kind=='software_ed25519':
        if config.get('require_hardware'):raise ValueError('hardware signing required')
        return SoftwareEd25519()
    if kind=='pkcs11_ed25519':
        allowed={'type','module','token_label','key_label','pin_file','allow_software_token'}
        if set(config)-allowed:raise ValueError('unknown PKCS#11 configuration')
        return PKCS11Ed25519(**{k:v for k,v in config.items() if k!='type'})
    raise ValueError('unsupported signing provider; no software fallback')
