"""Independent mutual-TLS audit witness and TPM quote verifier.

Run on a separately administered host. Same-host tests verify protocol behavior,
not protection against a privileged attacker controlling both hosts.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import ssl
import threading
import time
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from .transport import canonical,HTTPS
from .tpm import verify_quote


def b64(v):return base64.b64encode(v).decode()
def unb64(v):return base64.b64decode(v,validate=True)
def verify(public,message,signature,algorithm):
    if algorithm=='Ed25519' and isinstance(public,ed25519.Ed25519PublicKey):public.verify(signature,message)
    elif algorithm=='ECDSA-P256-SHA256' and isinstance(public,ec.EllipticCurvePublicKey) and public.curve.name=='secp256r1':
        public.verify(signature,message,ec.ECDSA(hashes.SHA256()))
    else:raise ValueError('signature algorithm/key mismatch')


class Rejected(ValueError):
    def __init__(self,status,message):self.status=status;self.message=message


class Witness:
    def __init__(self,config):
        self.config=config;self.lock=threading.RLock();self.pending={}
        path=Path(config['database']);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(path,check_same_thread=False);path.chmod(0o600)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS anchors(domain TEXT,node TEXT,seq INTEGER,event_hash TEXT,receipt TEXT,PRIMARY KEY(domain,node,seq))');self.db.commit()
        self.signer=serialization.load_pem_private_key(Path(config['receipt_key_file']).read_bytes(),password=None)
        if not isinstance(self.signer,ed25519.Ed25519PrivateKey):raise ValueError('Ed25519 witness receipt key required')
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    self.connection.settimeout(5)
                    lengths=self.headers.get_all('Content-Length',[])
                    if self.headers.get('Transfer-Encoding') or len(lengths)!=1:raise Rejected(400,'length required')
                    size=int(lengths[0])
                    if not 0<size<=131072:raise Rejected(413,'body too large')
                    raw=self.rfile.read(size)
                    if len(raw)!=size:raise Rejected(400,'incomplete body')
                    request=json.loads(raw)
                    fingerprint=hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                    result=owner.dispatch(self.path,request,fingerprint)
                    code=200
                except Rejected as e:code=e.status;result={'error':e.message}
                except Exception:code=400;result={'error':'invalid assurance request'}
                data=canonical(result);self.send_response(code);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store')
                self.send_header('Connection','close');self.end_headers();self.wfile.write(data)
        class Server(ThreadingHTTPServer):
            daemon_threads=True;request_queue_size=32
            def __init__(self,*args):self.slots=threading.BoundedSemaphore(32);super().__init__(*args)
            def process_request(self,request,address):
                if not self.slots.acquire(blocking=False):self.close_request(request);return
                try:super().process_request(request,address)
                except Exception:self.slots.release();raise
            def process_request_thread(self,*args):
                try:super().process_request_thread(*args)
                finally:self.slots.release()
            def finish_request(self,request,address):
                request.settimeout(5)
                try:
                    with owner.tls.wrap_socket(request,server_side=True) as secure:super().finish_request(secure,address)
                except (ssl.SSLError,OSError,TimeoutError):pass
        self.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.tls.minimum_version=ssl.TLSVersion.TLSv1_2
        self.tls.load_cert_chain(config['cert_file'],config['key_file']);self.tls.verify_mode=ssl.CERT_REQUIRED
        self.tls.load_verify_locations(config['client_ca'])
        self.server=Server((config.get('host','127.0.0.1'),int(config.get('port',0))),Handler)
        self.url='https://'+config.get('host','127.0.0.1')+':'+str(self.server.server_port)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True)
    def start(self):self.thread.start()
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)
        with self.lock:self.db.close()
    def sign(self,body):return {'body':body,'signature':b64(self.signer.sign(canonical(body)))}
    def registration(self,domain,node,fingerprint):
        if not isinstance(domain,str) or not isinstance(node,str):raise Rejected(400,'invalid target')
        record=self.config['nodes'].get(domain+'/'+node)
        if not record or fingerprint not in record['client_fingerprints']:raise Rejected(403,'node/transport identity denied')
        return record
    def latest(self,domain,node):
        row=self.db.execute('SELECT receipt FROM anchors WHERE domain=? AND node=? ORDER BY seq DESC LIMIT 1',(domain,node)).fetchone()
        return json.loads(row[0]) if row else None
    def dispatch(self,path,request,fingerprint):
        if type(request) is not dict:raise Rejected(400,'object required')
        domain=request.get('domain');node=request.get('node');record=self.registration(domain,node,fingerprint)
        with self.lock:
            if path=='/v1/head':return {'head':self.latest(domain,node)}
            if path=='/v1/anchors':
                if set(request)!={'domain','node','body','signature'}:raise Rejected(400,'invalid anchor fields')
                body=request['body'];required={'domain','node','sequence','previous_hash','event_hash','key_id','algorithm'}
                if type(body) is not dict or set(body)!=required or body['domain']!=domain or body['node']!=node or type(body['sequence']) is not int or body['sequence']<1:
                    raise Rejected(400,'invalid anchor body')
                import re
                if any(not isinstance(body[k],str) or not re.fullmatch('[a-f0-9]{64}',body[k]) for k in ('previous_hash','event_hash')):
                    raise Rejected(400,'invalid journal digests')
                if body['algorithm']!=record['algorithm'] or body['key_id']!=record['audit_key_id']:raise Rejected(403,'audit key binding denied')
                public=serialization.load_pem_public_key(Path(record['audit_public_file']).read_bytes())
                verify(public,canonical(body),unb64(request['signature']),body['algorithm'])
                digest=hashlib.sha256(canonical(body)).hexdigest();prior=self.latest(domain,node)
                if prior:
                    head=prior['body']
                    if body['sequence']==head['sequence'] and digest==head['anchor_sha256']:return prior
                    if body['sequence']!=head['sequence']+1 or body['previous_hash']!=head['event_hash']:raise Rejected(409,'fork, gap or rollback')
                elif body['sequence']!=1 or body['previous_hash']!='0'*64:raise Rejected(409,'genesis anchor required')
                receipt=self.sign({'domain':domain,'node':node,'sequence':body['sequence'],'event_hash':body['event_hash'],
                    'anchor_sha256':digest,'accepted_at':time.time()})
                with self.db:self.db.execute('INSERT INTO anchors VALUES(?,?,?,?,?)',(domain,node,body['sequence'],body['event_hash'],json.dumps(receipt)))
                return receipt
            now=time.monotonic();self.pending={k:v for k,v in self.pending.items() if v['expires']>now}
            if path=='/v1/attestation/challenge':
                if set(request)!={'domain','node','context'} or type(request['context']) is not dict:raise Rejected(400,'invalid attestation context')
                if request['context'].get('gateway_public_sha256')!=record['gateway_public_sha256']:raise Rejected(403,'gateway public-key binding denied')
                if len(self.pending)>=128 or sum(v['node']==node and v['domain']==domain for v in self.pending.values())>=16:raise Rejected(429,'challenge limit')
                nonce=secrets.token_hex(32)
                bound={'domain':domain,'node':node,'nonce':nonce,'context':request['context'],'client_certificate_sha256':fingerprint}
                qualifying=hashlib.sha256(canonical(bound)).hexdigest()
                self.pending[nonce]={'domain':domain,'node':node,'peer':fingerprint,'expires':now+30,'qualifying':qualifying,'context':request['context']}
                return {'nonce':nonce,'qualifying_hex':qualifying,'expires_in':30}
            if path=='/v1/attestation/verify':
                if set(request)!={'domain','node','nonce','evidence'}:raise Rejected(400,'invalid evidence fields')
                entry=self.pending.get(request['nonce'])
                if not entry or (entry['domain'],entry['node'],entry['peer'])!=(domain,node,fingerprint):raise Rejected(409,'challenge stale or replayed')
                del self.pending[request['nonce']]
                verify_quote(request['evidence'],entry['qualifying'],Path(record['attestation_public_file']).read_bytes(),
                    record['approved_pcr_sha256'],tools_dir=self.config.get('tools_dir',''))
                return self.sign({'domain':domain,'node':node,'nonce':request['nonce'],'qualifying_hex':entry['qualifying'],
                    'context_sha256':hashlib.sha256(canonical(entry['context'])).hexdigest(),'status':'accepted'})
            raise Rejected(404,'unknown endpoint')


class WitnessClient:
    def __init__(self,transport,domain,node,receipt_public_file):
        self.transport=transport;self.domain=domain;self.node=node
        self.public=serialization.load_pem_public_key(Path(receipt_public_file).read_bytes())
        if not isinstance(self.public,ed25519.Ed25519PublicKey):raise ValueError('Ed25519 witness key required')
    def post(self,path,body=None):return self.transport.post(path,{'domain':self.domain,'node':self.node,**(body or {})})
    def checked(self,receipt):
        if set(receipt)!={'body','signature'}:raise ValueError('invalid witness receipt')
        self.public.verify(unb64(receipt['signature']),canonical(receipt['body']))
        if receipt['body'].get('domain')!=self.domain or receipt['body'].get('node')!=self.node:raise ValueError('receipt target mismatch')
        return receipt['body']
    def head(self):
        receipt=self.post('/v1/head')['head'];return self.checked(receipt) if receipt else None
    def attest(self,tpm,context):
        challenge=self.post('/v1/attestation/challenge',{'context':context})
        evidence=tpm.quote(challenge['qualifying_hex'])
        result=self.checked(self.post('/v1/attestation/verify',{'nonce':challenge['nonce'],'evidence':evidence}))
        if result.get('status')!='accepted' or result.get('nonce')!=challenge['nonce'] or result.get('qualifying_hex')!=challenge['qualifying_hex'] or result.get('context_sha256')!=hashlib.sha256(canonical(context)).hexdigest():
            raise ValueError('attestation verdict binding mismatch')
        return result
    def anchor(self,journal,signer):
        # External head, rather than a host-local cursor, detects local rollback.
        with journal.lock:
            if not journal.verify_chain()['valid']:raise ValueError('local journal chain invalid')
            head=self.head();seq=head['sequence'] if head else 0
            if head:
                local=journal.db.execute('SELECT event_hash FROM events WHERE seq=?',(seq,)).fetchone()
                if not local or local[0]!=head['event_hash']:raise ValueError('local journal rolled back or forked from witness')
            while True:
                rows=journal.read(seq,500)
                if not rows:break
                for row in rows:
                    body={'domain':self.domain,'node':self.node,'sequence':row['sequence'],
                        'previous_hash':row['previous_hash'],'event_hash':row['event_hash'],
                        'key_id':signer.key_id,'algorithm':signer.algorithm}
                    receipt=self.checked(self.post('/v1/anchors',{'body':body,'signature':b64(signer.sign(canonical(body)))}))
                    if receipt.get('sequence')!=row['sequence'] or receipt.get('event_hash')!=row['event_hash'] or receipt.get('anchor_sha256')!=hashlib.sha256(canonical(body)).hexdigest():
                        raise ValueError('witness anchor receipt mismatch')
                    seq=row['sequence']
            return seq
