"""Generate the runtime fork while preserving every archived source byte."""
from pathlib import Path
import hashlib
ROOT = Path(__file__).resolve().parents[1]

def build():
    source = (ROOT/'published/engine.py').read_text()
    old = '    def __init__(self, authority, clock=None):\n'
    assert source.count(old) == 1
    source = source.replace(old, '    def __init__(self, authority, clock=None, key_provider=None):\n')
    old = '        self._sign = ed25519.Ed25519PrivateKey.generate()\n'
    # Other signing classes are deliberately unchanged.
    start = source.index('class Domain:')
    source = source[:start] + source[start:].replace(old,
        '        from enterprise.keys import SoftwareEd25519\n'
        '        self._sign = key_provider or SoftwareEd25519()\n'
        '        self.release_transform = lambda plaintext, body, grant: plaintext\n'
        '        self.admission_authority = lambda request: {}\n'
        '        self.operation_authority = lambda body, grant: None\n', 1)
    old = "            plaintext = self.objects[body['resource']][2]\n"
    assert source.count(old) == 1
    source = source.replace(old, old + '            plaintext = self.release_transform(plaintext, body, grant)\n')
    old = '            self.sessions[sid] = Session(copy.deepcopy(grant), key)\n'
    assert source.count(old) == 1
    source = source.replace(old, '            grant.update(self.admission_authority(request))\n' + old)
    old = '            plaintext = self.release_transform(plaintext, body, grant)\n'
    assert source.count(old) == 1
    source = source.replace(old, old + '            self.operation_authority(body, grant)\n')
    header = '# Generated runtime fork; original published/engine.py is unchanged.\n'
    header += '# Source SHA-256: ' + hashlib.sha256((ROOT/'published/engine.py').read_bytes()).hexdigest() + '\n'
    (ROOT/'runtime_engine.py').write_text(header + source)

if __name__ == '__main__': build()
