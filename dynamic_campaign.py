#!/usr/bin/env python3
"""Reproducible stateful action fuzzing, malformed inputs and real thread schedules."""
import copy,datetime,json,random,threading,time,unittest
from pathlib import Path
from engine import *
from reproduce_findings import probes,load
ROOT=Path(__file__).resolve().parent
rows=[]
def record(name,ok,detail=None):
 rows.append({'case':name,'pass':bool(ok),'detail':detail})
 if not ok:raise AssertionError(name+': '+repr(detail))

baseline=probes(load(ROOT/'before/engine.py','campaign_before'))
fixed=probes(load(ROOT/'engine.py','campaign_after'))
record('purpose_change_blocks_old_grant',baseline['F01_task_purpose_drift']=='RELEASED' and fixed['F01_task_purpose_drift']=='DENIED')
record('replacement_instance_blocks_old_grant',baseline['F02_rebound_instance_old_grant']=='RELEASED' and fixed['F02_rebound_instance_old_grant']=='DENIED')
record('malformed_request_is_controlled_denial',baseline['F04_malformed_envelope'].startswith('UNHANDLED') and fixed['F04_malformed_envelope']=='DENIED')
record('pending_challenge_quota',baseline['F05_challenge_pressure']['stored']==300 and fixed['F05_challenge_pressure']['stored']==16)
record('identity_commit_serializes_with_release',baseline['F03_identity_update_race']['identity_commit_while_request_paused'] and not fixed['F03_identity_update_race']['identity_commit_while_request_paused'])

# Seeded sequence oracle tracks authority validity independently of internal
# evaluator conditions. Each episode exercises valid and invalid states.
actions_count=0;release_count=0;denied_count=0
for episode in range(200):
 rng=random.Random(20261015+episode);auth,d,agents=fixture();a=agents['A'];sid=enroll(auth,d,a)
 valid=True;paused=False
 for step in range(25):
  action=rng.choice(['read','read','fresh','pause','resume','purpose','rotate','group','environment','revoke','policy'])
  actions_count+=1
  if action=='fresh':
   req=d.admission_request('A');req['purpose']=d.tasks['stock']['purpose']
   sid=enroll(auth,d,a,req);valid=True;paused=False
  elif action=='pause':
   if d.sessions[sid].state=='ACTIVE':d.checkpoint(sid,'PENDING');paused=True
  elif action=='resume':
   if d.sessions[sid].state=='ACTIVE':d.checkpoint(sid,'PASS');paused=False
  elif action=='purpose':d.update_task('stock',purpose='approved-objective-'+str(step));valid=False
  elif action=='rotate':a=Agent('A');d.register(a);valid=False
  elif action=='group':d.change_group('stock',set('ABCD'));valid=False
  elif action=='environment':d.change_environment('A');valid=False
  elif action=='revoke':d.revoke(sid);valid=False
  elif action=='policy':d.update_policy();valid=False
  elif action=='read':
   before=d.release_count
   try:
    envelope=d.operate(a.request(sid));allowed=True
    record(f'sequence_{episode}_{step}_decrypt',a.decrypt(envelope)==d.objects['inventory'][2])
   except Denied:allowed=False
   expected=valid and not paused
   record(f'sequence_{episode}_{step}_decision',allowed==expected,{'expected':expected,'observed':allowed})
   record(f'sequence_{episode}_{step}_release',d.release_count-before==int(expected))
   release_count+=int(allowed);denied_count+=int(not allowed)

# Malformed envelopes, including scalar/type/nesting/oversize/nonfinite values.
auth,d,agents=fixture();sid=enroll(auth,d,agents['A']);template=agents['A'].request(sid)
malformed=[None,[],{},'not an envelope',{'body':[]},{'body':{},'signature':'x'}]
for key in template['body']:
 for value in [None,[],{},True,'', 'x'*2048]:
  q=copy.deepcopy(template);q['body'][key]=value;malformed.append(q)
for value in [float('nan'),float('inf'),10**1000]:
 q=copy.deepcopy(template);q['body']['at']=value;malformed.append(q)
for number,q in enumerate(malformed):
 before=d.release_count
 try:d.operate(q);ok=False
 except Denied:ok=True
 record('malformed_'+str(number),ok and d.release_count==before)

# Exercise three real writer operations against concurrent valid reads. Evaluate
# audit release events after the update's committed return. Workers cannot
# legitimately use that old grant once the writer returns.
concurrency=[]
for kind in ['identity','task','policy','revoke','environment','group']:
 for trial in range(20):
  auth,d,agents=fixture();a=agents['A'];sid=enroll(auth,d,a)
  begin=threading.Barrier(4);committed=threading.Event();errors=[];old_after=[]
  def worker():
   try:
    begin.wait()
    for _ in range(40):
     after=committed.is_set()
     try:d.operate(a.request(sid));allowed=True
     except Denied:allowed=False
     if after and allowed:old_after.append(True)
   except Exception as exc:errors.append(repr(exc))
  def writer():
   try:
    begin.wait()
    if kind=='identity':d.register(Agent('A'))
    elif kind=='task':d.update_task('stock',purpose='new-approved-purpose')
    elif kind=='policy':d.update_policy()
    elif kind=='revoke':d.revoke(sid)
    elif kind=='environment':d.change_environment('A')
    elif kind=='group':d.change_group('stock',set('ABCD'))
    committed.set()
   except Exception as exc:errors.append(repr(exc))
  threads=[threading.Thread(target=worker) for _ in range(3)]+[threading.Thread(target=writer)]
  for t in threads:t.start()
  for t in threads:t.join(5)
  ok=not errors and not old_after and not any(t.is_alive() for t in threads) and committed.is_set()
  record(f'concurrent_{kind}_{trial}',ok,{'errors':errors,'old_releases_started_after_commit':len(old_after)})
  concurrency.append({'kind':kind,'trial':trial,'pass':ok})
# Positive quota recovery and request-budget controls.
auth,d,agents=fixture();req=d.admission_request('A')
for _ in range(16):d.challenge(req)
try:d.challenge(req);cap=False
except Denied:cap=True
record('challenge_capacity_enforced',cap)
d.clock.advance(11);record('expired_challenges_reclaimed',bool(d.challenge(req)) and len(d.challenges)==1)
auth,d,agents=fixture();sid=enroll(auth,d,agents['A']);d.max_requests_per_session=2
for _ in range(2):d.operate(agents['A'].request(sid))
try:d.operate(agents['A'].request(sid));budget=False
except Denied:budget=d.sessions[sid].state=='REVOKED'
record('request_budget_revokes_without_extra_release',budget and d.release_count==2)
result={'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'method':'Stateful scripted tool-action fuzzing and thread interleavings; NO live-model cognitive robustness benchmark',
 'episodes':200,'actions':actions_count,'observed_reads':{'released':release_count,'denied':denied_count},
 'malformed_envelopes':len(malformed),'concurrent_trials':len(concurrency),
 'assertions':len(rows),'passed':sum(r['pass'] for r in rows),'rows':rows,
 'before':baseline,'after':fixed,'concurrency':concurrency}
(ROOT/'dynamic_results.json').write_text(json.dumps(result,indent=2))
print(json.dumps({k:v for k,v in result.items() if k not in ['rows','before','after','concurrency']},indent=2))
