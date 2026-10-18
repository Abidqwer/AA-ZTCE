"""Same behavioral probes against old and tightened modules, with real signatures."""
import importlib.util,json,threading,time,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
 sys.modules[name]=m;spec.loader.exec_module(m);return m

def probes(m):
 out={}
 auth,d,agents=m.fixture();a=agents['A'];sid=m.enroll(auth,d,a)
 d.tasks['stock']['purpose']='changed-objective'
 try:d.operate(a.request(sid));out['F01_task_purpose_drift']='RELEASED'
 except m.Denied:out['F01_task_purpose_drift']='DENIED'
 auth,d,agents=m.fixture();sid=m.enroll(auth,d,agents['A']);replacement=m.Agent('A');d.register(replacement)
 try:d.operate(replacement.request(sid));out['F02_rebound_instance_old_grant']='RELEASED'
 except m.Denied:out['F02_rebound_instance_old_grant']='DENIED'
 auth,d,agents=m.fixture()
 try:d.operate({'body':[]});out['F04_malformed_envelope']='ACCEPTED'
 except m.Denied:out['F04_malformed_envelope']='DENIED'
 except Exception as e:out['F04_malformed_envelope']='UNHANDLED_'+type(e).__name__
 auth,d,agents=m.fixture();req=d.admission_request('A');admitted=0
 for _ in range(300):
  try:d.challenge(req);admitted+=1
  except m.Denied:pass
 out['F05_challenge_pressure']={'accepted':admitted,'stored':len(d.challenges)}
 # Pause an actual request immediately after signature validation. The old
 # unguarded register() can commit while this request still holds the lock.
 auth,d,agents=m.fixture();a=agents['A'];sid=m.enroll(auth,d,a)
 checked=threading.Event();resume=threading.Event();committed=threading.Event();errors=[];result={}
 original=d.identities['A']['sign']
 class GatedVerifier:
  def verify(self,*args):
   original.verify(*args);checked.set()
   if not resume.wait(3):raise RuntimeError('gate timeout')
  def public_bytes(self,*args,**kwargs):return original.public_bytes(*args,**kwargs)
 d.identities['A']['sign']=GatedVerifier()
 def operation():
  try:d.operate(a.request(sid));result['operation']='RELEASED'
  except m.Denied:result['operation']='DENIED'
  except Exception as e:errors.append(repr(e))
 def mutation():
  try:
   d.register(m.Agent('A'));result['release_count_at_identity_commit']=d.release_count;committed.set()
  except Exception as e:errors.append(repr(e))
 t=threading.Thread(target=operation);t.start()
 if not checked.wait(2):raise RuntimeError('request did not reach gate')
 u=threading.Thread(target=mutation);u.start()
 result['identity_commit_while_request_paused']=committed.wait(.15)
 resume.set();t.join(3);u.join(3)
 if t.is_alive() or u.is_alive() or errors:raise RuntimeError('race probe error '+repr(errors))
 result['release_count_final']=d.release_count
 out['F03_identity_update_race']=result
 return out

if __name__=='__main__':
 result={'before':probes(load(ROOT/'before/engine.py','before_engine')),
         'after':probes(load(ROOT/'engine.py','after_engine'))}
 (ROOT/'finding_reproductions.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
