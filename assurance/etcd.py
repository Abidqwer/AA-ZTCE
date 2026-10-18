"""Verified HTTPS etcd v3 gateway client. All Range calls are linearizable.

No local cached authorization and no fallback to standalone operation when this
profile is configured. This assumes trusted/crash-fault consensus participants.
"""
import base64
import json
import ssl
import threading
import urllib.error
import urllib.request


def b64(value):return base64.b64encode(value.encode() if isinstance(value,str) else value).decode()
def unb64(value):return base64.b64decode(value,validate=True)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


class ConsensusUnavailable(RuntimeError):pass
class AuthorityRevoked(ValueError):pass


class Etcd:
    def __init__(self,endpoints,ca_file,cert_file,key_file,*,timeout=2,username=None,password_file=None,allow_no_rbac=False):
        if not endpoints or any(not e.startswith('https://') for e in endpoints):raise ValueError('verified HTTPS endpoints required')
        if not username and not allow_no_rbac:raise ValueError('etcd RBAC credentials required')
        from pathlib import Path
        self.username=username;self.password=Path(password_file).read_text().strip() if username else None
        self.token=None
        self.endpoints=[e.rstrip('/') for e in endpoints];self.timeout=timeout
        context=ssl.create_default_context(cafile=ca_file);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file,key_file)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),NoRedirect())
        self.lock=threading.RLock();self.preferred=0
    def call(self,path,body):
        # Failover only changes transport endpoint; it never switches consistency.
        with self.lock:
            start=self.preferred
            for offset in range(len(self.endpoints)):
                i=(start+offset)%len(self.endpoints)
                headers={'Content-Type':'application/json'}
                if self.username:
                    try:
                        auth=urllib.request.Request(self.endpoints[i]+'/v3/auth/authenticate',
                            data=canonical({'name':self.username,'password':self.password}),headers=headers,method='POST')
                        with self.opener.open(auth,timeout=self.timeout) as response:self.token=json.loads(response.read(65536))['token']
                        headers['Authorization']=self.token
                    except Exception as error:
                        self.last_error=type(error).__name__+": "+str(error)[:120]
                        if isinstance(error,urllib.error.HTTPError):self.last_error+=error.read(512).decode(errors="replace")
                        continue
                req=urllib.request.Request(self.endpoints[i]+path,data=canonical(body),headers=headers,method='POST')
                try:
                    with self.opener.open(req,timeout=self.timeout) as response:
                        data=response.read(1048577)
                        if len(data)>1048576:raise ValueError('etcd response too large')
                        value=json.loads(data)
                        if 'error' in value:raise ValueError('etcd returned error')
                        self.preferred=i;return value
                except Exception as error:
                    self.last_error=type(error).__name__+": "+str(error)[:120]
                    if isinstance(error,urllib.error.HTTPError):self.last_error+=error.read(512).decode(errors="replace")
                    continue
        raise ConsensusUnavailable('consensus authority unavailable; operation denied')
    def range(self,key):return self.call('/v3/kv/range',{'key':b64(key),'serializable':False})
    def txn(self,compare,success,failure=()):return self.call('/v3/kv/txn',{'compare':compare,'success':success,'failure':list(failure)})


class Revocations:
    def __init__(self,client,domain_id,node_id,control_client=None):
        import re
        if any(not isinstance(s,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,80}',s) for s in (domain_id,node_id)):
            raise ValueError('invalid consensus domain/node ID')
        self.client=client;self.control_client=control_client;self.domain_id=domain_id;self.node_id=node_id
        self.prefix='/aa-ztce/v1/'+domain_id+'/'
    def key(self,kind,value):
        # Encoding avoids key/path collisions for arbitrary enrolled principal IDs.
        return self.prefix+kind+'/'+b64(value).replace('/','_').replace('+','-')
    def read(self,kind,name,client=None):
        key=self.key(kind,name);data=(client or self.client).range(key);items=data.get('kvs',[])
        return (json.loads(unb64(items[0]['value'])),int(items[0]['mod_revision'])) if items else (None,0)
    def compare(self,kind,name,revision):
        result={'key':b64(self.key(kind,name)),'target':'MOD' if revision else 'VERSION','result':'EQUAL'}
        result['mod_revision' if revision else 'version']=str(revision)
        return result
    def put(self,kind,name,value):return {'request_put':{'key':b64(self.key(kind,name)),'value':b64(canonical(value))}}
    def agent(self,name):
        value,rev=self.read('agent',name)
        return value or {'epoch':0,'disabled':False},rev
    def admission(self,request):
        state,_=self.agent(request['agent'])
        if state['disabled']:raise AuthorityRevoked('distributed identity disabled')
        return {'distributed':{'domain':self.domain_id,'agent_epoch':state['epoch']}}
    def authorize(self,body,grant):
        state,ar=self.agent(grant['agent']);session,sr=self.read('session',grant['sid'])
        binding=grant.get('distributed',{})
        if binding.get('domain')!=self.domain_id or state['disabled'] or binding.get('agent_epoch')!=state['epoch']:
            raise AuthorityRevoked('distributed authority revoked or changed')
        if session and session['state']!='ACTIVE':raise AuthorityRevoked('distributed session suspended or revoked')
        # This transaction is the authorization linearization point. A revocation
        # committed before it changes a comparison and prevents authorization.
        result=self.client.txn([self.compare('agent',grant['agent'],ar),self.compare('session',grant['sid'],sr)],
            [self.put('last_authorized',self.node_id,{'session_id':grant['sid'],'agent_id':grant['agent'],
                'request_id':body['request_id'],'epoch':state['epoch']})])
        if not result.get('succeeded'):raise AuthorityRevoked('authority changed concurrently; retry with fresh request')
        return int(result['header']['revision'])
    def change_session(self,sid,agent,state):
        if self.control_client is None:raise ConsensusUnavailable('external revocation control credentials required')
        for _ in range(8):
            old,rev=self.read('session',sid)
            if old and old.get('agent')!=agent:raise AuthorityRevoked('distributed session principal mismatch')
            if old and old['state']=='REVOKED':
                if state!='REVOKED':raise AuthorityRevoked('revoked session cannot be reactivated')
                return rev
            if old and old['state']==state:return rev
            value={'agent':agent,'state':state}
            result=self.control_client.txn([self.compare('session',sid,rev)],[self.put('session',sid,value)])
            if result.get('succeeded'):return int(result['header']['revision'])
        raise ConsensusUnavailable('concurrent session changes; no authority granted')
    def change_agent(self,agent,enabled=None,command_id=None):
        if self.control_client is None:raise ConsensusUnavailable('external revocation control credentials required')
        # A durable command record makes fresh-auth retries idempotent across nodes.
        if command_id:
            prior,_=self.read('command',command_id,self.control_client)
            if prior:
                if prior['agent']!=agent or prior['enabled']!=enabled:raise ValueError('distributed command conflict')
                return prior['epoch']
        for _ in range(8):
            old,rev=self.agent(agent)
            if enabled is not None and old['disabled']==(not enabled):return old['epoch']
            new={'epoch':old['epoch']+1,'disabled':old['disabled'] if enabled is None else not enabled}
            comparisons=[self.compare('agent',agent,rev)];writes=[self.put('agent',agent,new)]
            if command_id:
                comparisons.append(self.compare('command',command_id,0))
                writes.append(self.put('command',command_id,{'agent':agent,'enabled':enabled,'epoch':new['epoch']}))
            result=self.control_client.txn(comparisons,writes)
            if result.get('succeeded'):return new['epoch']
            if command_id:
                prior,_=self.read('command',command_id,self.control_client)
                if prior and prior['agent']==agent and prior['enabled']==enabled:return prior['epoch']
        raise ConsensusUnavailable('concurrent authority changes; no authority granted')


def install(domain,revocations):
    """Replicate supported lifecycle changes and bind each newly signed grant."""
    domain.distributed=revocations
    previous_admission=domain.admission_authority
    domain.admission_authority=lambda request:{**previous_admission(request),**revocations.admission(request)}
    previous_operation=domain.operation_authority
    def operation(body,grant):
        previous_operation(body,grant)
        return revocations.authorize(body,grant)
    domain.operation_authority=operation
    original_revoke=domain.revoke;original_checkpoint=domain.checkpoint;original_identity=domain.set_identity_enabled
    def revoke(sid,reason='manual'):
        with domain.lock:
            # A failed global commit must not keep local access alive.
            original_revoke(sid,reason)
            return revocations.change_session(sid,domain.sessions[sid].grant['agent'],'REVOKED')
    def checkpoint(sid,verdict):
        if verdict not in {'PASS','PENDING','FAIL'}:raise ValueError('invalid checkpoint')
        with domain.lock:
            session=domain.sessions[sid]
            if session.state!='ACTIVE':domain._deny('checkpoint cannot reactivate revoked session')
            revocations.change_session(sid,session.grant['agent'],{'PASS':'ACTIVE','PENDING':'PENDING','FAIL':'REVOKED'}[verdict])
            return original_checkpoint(sid,verdict)
    def identity(agent,enabled):
        if type(enabled) is not bool:raise ValueError('enabled must be boolean')
        with domain.lock:
            revocations.change_agent(agent,enabled)
            return original_identity(agent,enabled)
    domain.revoke=revoke;domain.checkpoint=checkpoint;domain.set_identity_enabled=identity
