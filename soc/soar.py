"""Signed, scoped SOAR response API with persistent replay/idempotency records."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
import re
import ssl
import threading
import time
import urllib.parse
from .events import canonical
from .ecs import to_ecs

ACTIONS={'revoke_session','suspend_session','require_reauth','disable_agent'}


class APIError(Exception):
    def __init__(self,status,message):self.status=status;self.message=message


def signature(secret,method,target,timestamp,nonce,body,audience='Domain-X'):
    value='\n'.join([method,target,audience,str(timestamp),nonce,hashlib.sha256(body).hexdigest()]).encode()
    return hmac.new(secret.encode(),value,hashlib.sha256).hexdigest()


def signed_headers(secret,key_id,method,target,body=b'',timestamp=None,nonce=None,audience='Domain-X'):
    import secrets
    timestamp=str(int(time.time()) if timestamp is None else timestamp)
    nonce=nonce or secrets.token_hex(24)
    return {'Content-Type':'application/json','X-AA-Key-ID':key_id,
            'X-AA-Timestamp':timestamp,'X-AA-Nonce':nonce,'X-AA-Audience':audience,
            'X-AA-Signature':signature(secret,method,target,timestamp,nonce,body,audience)}


class SOAR:
    def __init__(self,domain,journal,config):
        self.domain=domain;self.journal=journal;self.config=config;self.clients={}
        for client in config['clients']:
            item=dict(client)
            if item.get('key_file'):
                with open(item['key_file']) as f:item['secret']=f.read().strip()
            elif item.get('key_env'):item['secret']=os.environ.get(item['key_env'],'')
            if len(item.get('secret',''))<32:raise ValueError('SOAR client key must be at least 32 characters')
            if item['id'] in self.clients:raise ValueError('duplicate SOAR client ID')
            self.clients[item['id']]=item
        from enterprise.workflows import Workflows
        self.workflows=Workflows(domain,journal)
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def setup(self):
                super().setup();self.connection.settimeout(5)
            def log_message(self,*args):pass
            def respond(self,status,data):
                content=canonical(data);self.send_response(status)
                self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store')
                self.send_header('Content-Length',str(len(content)));self.send_header('Connection','close')
                self.end_headers();self.wfile.write(content);self.close_connection=True
            def serve(self):
                principal=None
                try:
                    if self.command=='GET' and self.path=='/health':
                        self.respond(200,{'status':'ok'});return
                    if self.headers.get('Transfer-Encoding'):raise APIError(400,'chunked requests unsupported')
                    lengths=self.headers.get_all('Content-Length',[])
                    if len(lengths)>1:raise APIError(400,'duplicate length')
                    try:length=int(lengths[0]) if lengths else 0
                    except ValueError:raise APIError(400,'invalid length')
                    if length<0 or length>16384:raise APIError(413,'body too large')
                    body=self.rfile.read(length)
                    if len(body)!=length:raise APIError(400,'incomplete body')
                    principal=owner.authenticate(self.command,self.path,self.headers,body)
                    if self.path.startswith('/v1/workflows/'):
                        from enterprise.workflows import WorkflowError
                        try:
                            document=json.loads(body) if body else None
                            result=owner.workflows.handle(principal,self.command,self.path[len('/v1/workflows/'):],document)
                        except WorkflowError as e: raise APIError(e.status,e.message)
                        except (ValueError,TypeError):raise APIError(400,'invalid workflow document')
                    elif self.command=='POST' and self.path=='/v1/actions':
                        try:request=json.loads(body)
                        except Exception:raise APIError(400,'invalid JSON')
                        result=owner.execute(principal,request)
                    elif self.command=='GET' and urllib.parse.urlsplit(self.path).path=='/v1/events':
                        if 'read_events' not in principal['actions']:raise APIError(403,'event scope denied')
                        query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                        if set(query)-{'after','limit'} or any(len(v)!=1 for v in query.values()):
                            raise APIError(400,'invalid query parameters')
                        try:after=int(query.get('after',['0'])[0]);limit=int(query.get('limit',['100'])[0])
                        except ValueError:raise APIError(400,'invalid cursor')
                        if after<0 or not 1<=limit<=500:raise APIError(400,'cursor or limit out of range')
                        events=owner.journal.read(after,limit)
                        allowed=set(principal['agents'])
                        visible=events if '*' in allowed else [e for e in events if e.get('agent_id') in allowed]
                        result={'events':[to_ecs(e) for e in visible],'next_after':events[-1]['sequence'] if events else after}
                    else:raise APIError(404,'unknown endpoint')
                    self.respond(200,result)
                except APIError as e:
                    try:
                        owner.journal.append('soar.request.denied',actor_id=principal['id'] if principal else None,
                            outcome='denied',reason_code='authentication_failed' if e.status==401 else
                            'scope_denied' if e.status==403 else 'request_rejected',severity=7)
                    except Exception:
                        self.respond(503,{'error':'audit unavailable'});return
                    self.respond(e.status,{'error':e.message})
                except Exception:self.respond(503,{'error':'operation unavailable; retry with same command ID'})
            do_GET=serve
            do_POST=serve
            do_PUT=serve
            do_DELETE=serve
        class Server(ThreadingHTTPServer):
            daemon_threads=True
            request_queue_size=32
            def __init__(self,*args,**kwargs):
                self.slots=threading.BoundedSemaphore(32);self.tls_context=None;super().__init__(*args,**kwargs)
            def finish_request(self,request,address):
                if self.tls_context:
                    request.settimeout(5)
                    wrapped=self.tls_context.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
                    try:
                        wrapped.do_handshake();super().finish_request(wrapped,address)
                    except (ssl.SSLError,TimeoutError,OSError):
                        try:owner.journal.append('soar.transport.denied',outcome='denied',reason_code='tls_failed',severity=7)
                        except Exception:pass
                    finally:wrapped.close()
                else:super().finish_request(request,address)
            def process_request(self,request,address):
                if not self.slots.acquire(blocking=False):self.close_request(request);return
                try:super().process_request(request,address)
                except Exception:self.slots.release();raise
            def process_request_thread(self,request,address):
                try:super().process_request_thread(request,address)
                finally:self.slots.release()
        host=config.get('host','127.0.0.1')
        # Direct exposure is permitted only with TLS; optional mTLS uses a dedicated client CA.
        self.server=Server((host,int(config.get('port',0))),Handler)
        if config.get('cert_file'):
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(config['cert_file'],config['key_file'])
            if config.get('client_ca'):
                ctx.verify_mode=ssl.CERT_REQUIRED;ctx.load_verify_locations(config['client_ca'])
            self.server.tls_context=ctx
            scheme='https'
        elif config.get('allow_loopback_http') and host in ('127.0.0.1','::1'):
            scheme='http'
        else:self.server.server_close();raise ValueError('TLS required for SOAR listener')
        self.url=f'{scheme}://{host}:{self.server.server_port}'
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.1},daemon=True)
    def start(self):self.thread.start()
    def authenticate(self,method,target,headers,body):
        if any(len(headers.get_all(name,[]))!=1 for name in ('X-AA-Key-ID','X-AA-Audience','X-AA-Timestamp','X-AA-Nonce','X-AA-Signature')):
            raise APIError(401,'authentication failed')
        key=headers.get('X-AA-Key-ID','');client=self.clients.get(key)
        stamp=headers.get('X-AA-Timestamp','');nonce=headers.get('X-AA-Nonce','')
        supplied=headers.get('X-AA-Signature','')
        audience=headers.get('X-AA-Audience','')
        try:fresh=abs(time.time()-int(stamp))<=90
        except ValueError:fresh=False
        if not client or not fresh or audience!=self.journal.domain_id or not re.fullmatch('[a-f0-9]{32,128}',nonce):
            raise APIError(401,'authentication failed')
        expected=signature(client['secret'],method,target,stamp,nonce,body,audience)
        if not hmac.compare_digest(supplied,expected):raise APIError(401,'authentication failed')
        with self.journal.lock,self.journal.db:
            self.journal.db.execute('DELETE FROM nonces WHERE expires<?',(time.time(),))
            exists=self.journal.db.execute('SELECT 1 FROM nonces WHERE client_id=? AND nonce=?',(key,nonce)).fetchone()
            if exists:raise APIError(409,'nonce replay')
            self.journal.db.execute('INSERT INTO nonces VALUES(?,?,?)',(key,nonce,time.time()+180))
        return client
    def execute(self,client,request):
        required={'action','agent_id','command_id','case_id'}
        if (not isinstance(request,dict) or not required<=request.keys()
            or set(request)-required-{'session_id'}
            or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,128}',v) for v in request.values())):
            raise APIError(400,'invalid action schema')
        action=request['action'];agent=request['agent_id'];sid=request.get('session_id')
        if action not in ACTIONS:raise APIError(400,'unsupported response action')
        if action not in client['actions'] or ('*' not in client['agents'] and agent not in client['agents']):
            raise APIError(403,'action or target scope denied')
        if action.endswith('_session') and not sid:raise APIError(400,'session ID required')
        if action in ('require_reauth','disable_agent') and sid:raise APIError(400,'agent action cannot target one session')
        digest=hashlib.sha256(canonical(request)).hexdigest();command=request['command_id']
        with self.domain.lock:
            if agent not in self.domain.identities:raise APIError(404,'unknown target')
            if sid and (sid not in self.domain.sessions or self.domain.sessions[sid].grant['agent']!=agent):
                raise APIError(403,'session/agent mismatch')
            with self.journal.lock,self.journal.db:
                row=self.journal.db.execute('SELECT body_hash,status,result FROM commands WHERE client_id=? AND command_id=?',
                                           (client['id'],command)).fetchone()
                if row and row[0]!=digest:raise APIError(409,'command ID conflict')
                if row and row[1]=='complete':return {**json.loads(row[2]),'duplicate':True}
                if not row:self.journal.db.execute('INSERT INTO commands VALUES(?,?,?,?,?)',
                    (client['id'],command,digest,'pending',None))
            self.journal.append('soar.action.requested',actor_id=client['id'],agent_id=agent,
                session_id=sid,command_id=command,case_id=request['case_id'],operation=action,severity=6)
            distributed=getattr(self.domain,'distributed',None)
            if distributed and action in ('require_reauth','disable_agent'):
                distributed.change_agent(agent,False if action=='disable_agent' else None,
                    command_id=client['id']+':'+command)
            affected=[]
            if action=='revoke_session':
                self.domain.revoke(sid,'SOAR response');affected=[sid]
            elif action=='suspend_session':
                if self.domain.sessions[sid].state=='ACTIVE':self.domain.checkpoint(sid,'PENDING')
                affected=[sid]
                self.journal.append('checkpoint.pending',agent_id=agent,session_id=sid,
                                    actor_id=client['id'],command_id=command,severity=6)
            else:
                if action=='disable_agent' and self.domain.identities[agent]['enabled']:
                    self.domain.set_identity_enabled(agent,False)
                for session_id,session in self.domain.sessions.items():
                    if session.grant['agent']==agent:
                        self.domain.revoke(session_id,'SOAR fresh admission required');affected.append(session_id)
                self.journal.append('identity.disabled' if action=='disable_agent' else 'identity.reauthentication_required',
                                    agent_id=agent,actor_id=client['id'],command_id=command,severity=7)
            result={'command_id':command,'action':action,'agent_id':agent,'status':'applied',
                    'affected_sessions':affected,'duplicate':False}
            if distributed:result['distributed']={'status':'committed','scope':'configured consensus domain; per-node actuation not acknowledged'}
            self.journal.append('soar.action.completed',actor_id=client['id'],agent_id=agent,
                session_id=sid,command_id=command,case_id=request['case_id'],operation=action,outcome='success',severity=5)
            with self.journal.lock,self.journal.db:
                self.journal.db.execute("UPDATE commands SET status='complete',result=? WHERE client_id=? AND command_id=?",
                                        (canonical(result).decode(),client['id'],command))
            return result
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)
