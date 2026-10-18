"""Synthetic single-pod sandbox with managed configuration; no automatic PKI."""
import argparse
import json
from pathlib import Path
import signal
import threading
from verify import Deployment


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);args=p.parse_args()
    config=json.loads(Path(args.config).read_text())
    if config['soar'].get('port') != 8443 or config['soar'].get('host') != '0.0.0.0':
        raise ValueError('chart profile requires TLS listener 0.0.0.0:8443')
    if not config['soar'].get('client_ca'):raise ValueError('chart profile requires mutual TLS')
    if not all(config['soar'].get(k) for k in ('cert_file','key_file')):raise ValueError('managed TLS required')
    stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *x:stop.set());signal.signal(signal.SIGINT,lambda *x:stop.set())
    deployment=Deployment('hardened',soc=config)
    try:
        sessions={name:deployment.enroll(name)['sid'] for name in 'ABCD'}
        print(json.dumps({'status':'ready','profile':'synthetic-single-host','sessions':sessions}),flush=True)
        while not stop.wait(20):
            for worker in deployment.workers.values():worker.rpc(op='health')
    finally:deployment.close()

if __name__=='__main__':main()
