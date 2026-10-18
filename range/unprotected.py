"""Deliberately unprotected comparator; fixed synthetic files only, no shell tools.

Private stdin/stdout transport. A data release copies bytes to a local quarantine
file; destination='external' never causes an external network request.
"""
import json
from pathlib import Path
import sys


def main():
    root=Path(sys.argv[1]);resources={p.stem:p for p in root.glob('*.synthetic')}
    output=root/'quarantine';output.mkdir(exist_ok=True)
    for line in sys.stdin:
        try:
            item=json.loads(line);action=item['action'];resource=item['resource']
            if action=='noop':reply={'ok':True,'effect':'none'}
            elif resource not in resources:reply={'ok':False,'error':'unknown synthetic resource'}
            elif action=='read':
                data=resources[resource].read_text()
                (output/'last-release.txt').write_text(data)
                reply={'ok':True,'plaintext':data,'effect':'synthetic_data_released','quarantined':True}
            elif action=='delete':
                # Only fixed synthetic registry paths can be modified.
                resources[resource].write_text('DELETED SYNTHETIC RECORD')
                reply={'ok':True,'effect':'synthetic_data_deleted'}
            else:reply={'ok':False,'error':'unsupported action'}
        except Exception:reply={'ok':False,'error':'invalid bounded synthetic command'}
        print(json.dumps(reply),flush=True)

if __name__=='__main__':main()
