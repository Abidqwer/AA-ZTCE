"""Persistent local sandbox runtime with real gateway, four workers and SOAR API."""
import argparse
import json
from pathlib import Path
import signal
import threading
from verify import Deployment
from soc.setup import initialize


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--directory',default='soc_state');args=parser.parse_args()
    config=initialize(args.directory);stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *x:stop.set());signal.signal(signal.SIGINT,lambda *x:stop.set())
    deployment=Deployment('hardened',soc=config)
    try:
        sessions={name:deployment.enroll(name)['sid'] for name in 'ABCD'}
        ready={'soar_url':deployment.boot['soar_url'],'domain_id':config['domain_id'],
               'sessions':sessions,'config':str(Path(args.directory).resolve()/'soc-config.json'),
               'notice':'local synthetic sandbox; grants expire after 60 seconds'}
        (Path(args.directory)/'runtime.json').write_text(json.dumps(ready,indent=2))
        print(json.dumps(ready,indent=2),flush=True)
        while not stop.wait(20):
            # Keep healthy workers connected without silently restoring revoked permissions.
            for worker in deployment.workers.values():worker.rpc(op='health')
    finally:deployment.close()


if __name__=='__main__':main()
