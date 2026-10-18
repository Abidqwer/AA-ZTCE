#!/usr/bin/env python3
"""Run real TLS collectors, signed SOAR actions and the confined TCP deployment."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socketserver
import socket
import ssl
import sqlite3
import statistics
import tempfile
import threading
import time
import uuid
from verify import Deployment
from soc.client import request
from soc.events import Journal,canonical
from soc.setup import initialize
from soc.siem import Exporter
from soc.soar import signed_headers

ROOT=Path(__file__).resolve().parent


def run(output):
    output.mkdir(parents=True,exist_ok=True);checks=[];received=[];syslog=[]
    def check(name,condition,detail=None):
        checks.append({'name':name,'passed':bool(condition),'detail':detail})
        print(('PASS ' if condition else 'FAIL ')+name,flush=True)
    with tempfile.TemporaryDirectory(prefix='aa-soc-') as temp:
        config=initialize(temp);tls=config['soar'];secret=Path(tls['clients'][0]['key_file']).read_text().strip()
        config['soar']['client_ca']=tls['cert_file']  # Exercise mTLS, not only server-auth TLS.
        config['soar']['clients'].append({'id':'limited','secret':secrets.token_hex(32),
            'actions':['read_events','suspend_session'],'agents':['A']})
        limited=config['soar']['clients'][1]['secret']
        hec_token=secrets.token_hex(24);os.environ['AA_TEST_HEC_TOKEN']=hec_token
        class Collector(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                data=self.rfile.read(int(self.headers['Content-Length']));path=self.path
                valid=self.headers.get('Authorization')=='Splunk '+hec_token if path=='/hec' else True
                if path=='/json' and not getattr(self.server,'failed_once',False):
                    self.server.failed_once=True;self.send_response(503);self.end_headers();return
                if path=='/bulk':
                    lines=data.splitlines();item=json.loads(lines[0]);document=json.loads(lines[1])
                    reply={'errors':False,'items':[{'create':{'status':201}}]}
                    received.append({'sink':path,'event':document,'id':item['create']['_id'],'auth':valid})
                else:
                    item=json.loads(data);document=item['event'] if path=='/hec' else item
                    received.append({'sink':path,'event':document,'auth':valid})
                    reply={'code':0} if path=='/hec' else {'accepted':True}
                body=json.dumps(reply).encode();self.send_response(200)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        collector=ThreadingHTTPServer(('127.0.0.1',0),Collector)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(tls['cert_file'],tls['key_file'])
        collector.socket=ctx.wrap_socket(collector.socket,server_side=True)
        collector_thread=threading.Thread(target=collector.serve_forever,kwargs={'poll_interval':0.05},daemon=True);collector_thread.start()
        class SyslogHandler(socketserver.StreamRequestHandler):
            def handle(self):
                length=b''
                while True:
                    char=self.rfile.read(1)
                    if char==b' ':break
                    if not char or len(length)>10:return
                    length+=char
                line=self.rfile.read(int(length));syslog.append(line.decode())
        class SyslogServer(socketserver.ThreadingTCPServer):daemon_threads=True
        slog=SyslogServer(('127.0.0.1',0),SyslogHandler);slog.socket=ctx.wrap_socket(slog.socket,server_side=True)
        slog_thread=threading.Thread(target=slog.serve_forever,kwargs={'poll_interval':0.05},daemon=True);slog_thread.start()
        base=f'https://127.0.0.1:{collector.server_port}'
        config['siem_sinks']=[
            {'id':'json','type':'json_webhook','url':base+'/json','ca_file':tls['cert_file']},
            {'id':'hec','type':'splunk_hec','url':base+'/hec','ca_file':tls['cert_file'],'token_env':'AA_TEST_HEC_TOKEN'},
            {'id':'elastic','type':'elastic_bulk','url':base+'/bulk','ca_file':tls['cert_file']},
            {'id':'syslog','type':'syslog_tls','host':'127.0.0.1','port':slog.server_address[1],'ca_file':tls['cert_file']}]
        deployment=None
        try:
            deployment=Deployment('hardened',soc=config);url=deployment.boot['soar_url']
            clientkw={'ca_file':tls['cert_file'],'cert_file':tls['cert_file'],'key_file':tls['key_file']}
            def api(method,target,body=None,key='soc-operator',password=None,headers=None):
                return request(url,key,password or secret,method,target,body,headers=headers,**clientkw)
            def action(name,agent,sid=None,**changes):
                body={'action':name,'agent_id':agent,'command_id':str(uuid.uuid4()),'case_id':'CASE-001'}
                if sid:body['session_id']=sid
                body.update(changes);return body
            from urllib.parse import urlsplit
            endpoint=urlsplit(url);idle=socket.create_connection((endpoint.hostname,endpoint.port),timeout=2)
            try:
                check('idle TLS peer cannot block other authenticated requests',api('GET','/v1/events')[0]==200)
            finally:idle.close()
            check('API rejects out-of-contract event cursor',api('GET','/v1/events?after=-1')[0]==400)
            A=deployment.workers['A'];sid=deployment.enroll('A')['sid']
            check('SOC-enabled authorized encrypted read',A.call('operate',sid=sid).get('ok'))
            body=action('suspend_session','A',sid)
            start=time.perf_counter();status,reply=api('POST','/v1/actions',body)
            latency=[(time.perf_counter()-start)*1000]
            check('mTLS + signed SOAR suspension applied',status==200 and reply['status']=='applied')
            check('suspension blocks protected operation',not A.call('operate',sid=sid).get('ok'))
            status,duplicate=api('POST','/v1/actions',body)
            check('fresh-nonce retry returns idempotent result',status==200 and duplicate.get('duplicate'))
            conflict={**body,'action':'revoke_session'}
            check('command ID cannot change action',api('POST','/v1/actions',conflict)[0]==409)
            replay_body=action('require_reauth','A');headers=signed_headers(secret,'soc-operator','POST','/v1/actions',canonical(replay_body))
            check('signed fresh-authentication command accepted',api('POST','/v1/actions',replay_body,headers=headers)[0]==200)
            check('exact signed request replay rejected',api('POST','/v1/actions',replay_body,headers=headers)[0]==409)
            check('fresh authentication revokes previous sessions',not A.call('operate',sid=sid).get('ok'))
            new_sid=deployment.enroll('A')['sid']
            check('fresh authenticated admission still works',A.call('operate',sid=new_sid).get('ok'))
            tampered={**replay_body,'agent_id':'B'}
            headers=signed_headers(secret,'soc-operator','POST','/v1/actions',canonical(replay_body))
            check('body tampering invalidates signature',api('POST','/v1/actions',tampered,headers=headers)[0]==401)
            headers=signed_headers(secret,'soc-operator','POST','/v1/actions',canonical(replay_body),timestamp=int(time.time())-200)
            check('stale signed request rejected',api('POST','/v1/actions',replay_body,headers=headers)[0]==401)
            headers=signed_headers(secret,'soc-operator','POST','/v1/actions',canonical(replay_body),audience='Other-Domain')
            check('cross-domain signed command rejected',api('POST','/v1/actions',replay_body,headers=headers)[0]==401)
            check('wrong signing key rejected',api('POST','/v1/actions',body,password='x'*64)[0]==401)
            check('RBAC blocks disallowed action',api('POST','/v1/actions',action('disable_agent','A'),key='limited',password=limited)[0]==403)
            check('RBAC blocks another target agent',api('POST','/v1/actions',action('suspend_session','B',new_sid),key='limited',password=limited)[0]==403)
            check('session cannot be substituted across agents',api('POST','/v1/actions',action('revoke_session','B',new_sid))[0]==403)
            try:
                request(url,'soc-operator',secret,'GET','/v1/events',ca_file=tls['cert_file'])
                missing_client_cert=False
            except Exception:missing_client_cert=True
            check('mTLS refuses a client without certificate',missing_client_cert)
            try:
                request(url,'soc-operator',secret,'GET','/v1/events',cert_file=tls['cert_file'],key_file=tls['key_file'])
                bad_trust=False
            except Exception:bad_trust=True
            check('untrusted server certificate rejected',bad_trust)
            sid=deployment.enroll('A')['sid'];A.call('operate',sid=sid,arguments={'resource':'defence'})
            sid=deployment.enroll('A')['sid'];deployment.admin('checkpoint',sid=sid,verdict='FAIL')
            sid=deployment.enroll('A')['sid'];deployment.admin('update_task',task_id='stock',purpose='inventory-audit')
            A.call('operate',sid=sid)
            deployment.admin('update_task',task_id='stock',purpose='inventory-analysis')
            deployment.admin('set_identity_enabled',agent='B',enabled=False)
            check('SOAR disable-agent action applied',api('POST','/v1/actions',action('disable_agent','C'))[0]==200)
            check('disabled agent cannot obtain admission',not deployment.enroll('C').get('ok'))
            sid=deployment.enroll('D')['sid']
            check('SOAR revocation applied',api('POST','/v1/actions',action('revoke_session','D',sid))[0]==200)
            check('SOAR revocation blocks next operation',not deployment.workers['D'].call('operate',sid=sid).get('ok'))
            for _ in range(20):
                sid=deployment.enroll('A')['sid'];body=action('revoke_session','A',sid)
                start=time.perf_counter();status,_=api('POST','/v1/actions',body)
                latency.append((time.perf_counter()-start)*1000)
                if status!=200:raise RuntimeError('latency action failed')
            j=Journal(Path(temp)/'soc.sqlite','Domain-X')
            deadline=time.monotonic()+12
            while j.pending() and time.monotonic()<deadline:time.sleep(0.1)
            check('durable outbox drained to all four TLS collectors',j.pending()==0,{'pending':j.pending()})
            check('temporary SIEM failure retried',getattr(collector,'failed_once',False))
            check('hash chain verifies',j.verify_chain()['valid'],j.verify_chain())
            events=j.read(0,500);expected={e['event_id'] for e in events}
            for path in ('/json','/hec','/bulk'):
                docs=[row for row in received if row['sink']==path]
                check('collector delivery '+path,{r['event']['event']['id'] for r in docs}==expected)
                check('ECS fields and types '+path,all('@timestamp' in r['event'] and isinstance(r['event']['event']['category'],list)
                    and isinstance(r['event']['event']['type'],list) and r['event']['ecs']['version']=='8.17.0' for r in docs))
            check('Splunk HEC token/header verified',all(r['auth'] for r in received if r['sink']=='/hec'))
            check('Elasticsearch document IDs support deduplication',all(r['id']==r['event']['event']['id'] for r in received if r['sink']=='/bulk'))
            check('syslog TLS octet-counted event delivery',len(syslog)==len(events) and all('>1 ' in line for line in syslog))
            types={e['event_type'] for e in events}
            check('required SOC event coverage',{'checkpoint.fail','decision.denied','identity.changed','session.revoked'}<=types,sorted(types))
            check('approved task changes retain distinct non-scope reason code',
                  any(e.get('reason_code')=='task_changed' for e in events))
            check('events exclude protected data and authentication keys',deployment.canary not in json.dumps(events) and secret not in json.dumps(events)
                  and hec_token not in json.dumps(events))
            status,visible=api('GET','/v1/events?after=0&limit=500',key='limited',password=limited)
            check('event retrieval honors agent scope',status==200 and all(e.get('user',{}).get('id')=='A' for e in visible['events']))
            (output/'events_internal.json').write_text(json.dumps(events,indent=2))
            ecs=[r['event'] for r in received if r['sink']=='/json']
            (output/'events.ecs.ndjson').write_text(''.join(json.dumps(e)+'\n' for e in ecs))
            tamper=sqlite3.connect(Path(temp)/'tamper.sqlite');j.db.backup(tamper)
            tamper.execute("UPDATE events SET payload='{}' WHERE seq=1");tamper.commit();tamper.close()
            changed=Journal(Path(temp)/'tamper.sqlite','Domain-X')
            check('hash-chain check detects local event modification',not changed.verify_chain()['valid']);changed.close()
            j.close()
            # Reopen to check persistent replay/idempotency/audit state survives reader restart.
            j=Journal(Path(temp)/'soc.sqlite','Domain-X')
            check('journal survives close/reopen',j.verify_chain()['valid'] and len(j.read(0,500))==len(events))
            check('command history persisted',j.db.execute("SELECT COUNT(*) FROM commands WHERE status='complete'").fetchone()[0]>=20)
            j.close()
            recovery=Journal(Path(temp)/'recovery/soc.sqlite','Domain-X',['retry'])
            recovery.append('session.revoked',agent_id='A',outcome='success',severity=4)
            bad={'id':'retry','type':'json_webhook','url':'https://127.0.0.1:9/json','ca_file':tls['cert_file']}
            Exporter(recovery,[bad]).flush_once()
            check('SIEM connection failure leaves durable pending event',recovery.pending()==1)
            recovery.close();recovery=Journal(Path(temp)/'recovery/soc.sqlite','Domain-X',['retry'])
            time.sleep(0.45)
            Exporter(recovery,[{**bad,'url':base+'/json'}]).flush_once()
            check('outbox retries successfully after database reopen',recovery.pending()==0);recovery.close()
            metrics={'samples':len(latency),'median_ms':statistics.median(latency),
                     'p95_ms':sorted(latency)[int(0.95*(len(latency)-1))],
                     'scope':'single-host TLS+mTLS+HMAC+SQLite+gateway action; not a production SLO'}
            (output/'soar_latency.json').write_text(json.dumps(metrics,indent=2))
        finally:
            if deployment:deployment.close()
            collector.shutdown();collector.server_close();slog.shutdown();slog.server_close()
            os.environ.pop('AA_TEST_HEC_TOKEN',None)
    result={'checks':checks,'passed':sum(c['passed'] for c in checks),'total':len(checks),
            'vendor_platforms_tested':False,'method':'local TLS protocol collectors + separate confined workers'}
    (output/'soc_results.json').write_text(json.dumps(result,indent=2));print(json.dumps({'passed':result['passed'],'total':result['total']}))
    if result['passed']!=result['total']:raise SystemExit(1)


if __name__=='__main__':run(ROOT/'results/soc')
