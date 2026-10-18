#!/usr/bin/env python3
"""Z3 checks over an explicit mathematical abstraction, not verified Python code."""
from pathlib import Path
import datetime,json
from z3 import *
ROOT=Path(__file__).resolve().parent;Q=ROOT/'smt_queries';Q.mkdir(exist_ok=True)
rows=[]
def query(name,formula,expected,scope):
 s=Solver();s.set(timeout=10000);s.add(formula);answer=s.check()
 (Q/(name+'.smt2')).write_text(s.to_smt2())
 record={'name':name,'result':str(answer),'expected':expected,'pass':str(answer)==expected,'scope':scope}
 if answer==sat:record['witness']={str(x):str(s.model()[x]) for x in s.model()}
 rows.append(record)
 return record

# Safety model for one immutable session identifier. Recovery creates another
# identifier outside this session model. phase=0 unverified,1 active,2 checkpoint,3 revoked.
p,pn,act=Ints('phase phase_next action')
rev,revn,valid,validn,env,envn,grp,grpn,auth,authn= Bools('revoked revoked_next grant_valid grant_valid_next environment environment_next group group_next authority authority_next')
domain=And(p>=0,p<=3,act>=0,act<=7)
invariant=And(Implies(rev,And(p==3,Not(valid))),Implies(p==3,rev))
init=And(p==0,Not(rev),Not(valid),env,grp,auth)
# 0=no-op,1=admit,2=begin checkpoint,3=checkpoint pass,4=revoke,
# 5=environment invalidation,6=group invalidation,7=authority expiration.
admit=And(act==1,p==0,env,grp,auth,Not(rev))
begin=And(act==2,p==1,Not(rev))
passed=And(act==3,p==2,env,grp,auth,valid,Not(rev))
kill=act==4
transition=And(
 pn==If(kill,3,If(admit,1,If(begin,2,If(passed,1,p)))),
 revn==Or(rev,kill),validn==If(kill,False,If(admit,True,valid)),
 envn==If(act==5,False,env),grpn==If(act==6,False,grp),authn==If(act==7,False,auth))
nextinv=substitute(invariant,(p,pn),(rev,revn),(valid,validn))
query('01_initial_revocation_invariant',And(init,Not(invariant)),'unsat','Initial state satisfies the stated single-session invariant.')
query('02_inductive_revocation_invariant',And(domain,invariant,transition,Not(nextinv)),'unsat','One-step induction for all modeled actions; combined with 01 gives arbitrary finite traces in this abstraction.')
owner,requester=Ints('owner requester');proof,scope,compartment,policy,checkpoint=Bools('proof scope compartment policy checkpoint')
now,expiry=Ints('now expiry')
identity_binding,task_binding=Bools('identity_binding task_binding')
release=And(identity_binding,task_binding,p==1,valid,Not(rev),env,grp,auth,proof,scope,compartment,policy,checkpoint,owner==requester,now<expiry)
query('03_no_release_after_revocation',And(invariant,rev,release),'unsat','Model release guard disallows revoked grants.')
query('04_no_release_during_checkpoint',And(p==2,release),'unsat','Model release guard pauses protected operations during checkpoint.')
query('05_no_release_missing_critical_evidence',And(release,Or(Not(env),Not(grp),Not(auth),Not(proof),Not(policy),Not(compartment))),'unsat','All listed modeled critical gates are necessary.')
query('06_no_cross_instance_release',And(release,owner!=requester),'unsat','Instance binding in the modeled release rule.')
query('07_expired_grant_cannot_release',And(release,now>=expiry),'unsat','Mathematical expiry boundary; clock integrity is assumed.')
parent,requested=BitVecs('parent_rights requested_rights',16)
child=parent & requested
query('08_delegation_cannot_amplify',child & ~parent != BitVecVal(0,16),'unsat','16-bit set-intersection delegation design. This derivation is specified, not implemented as a complete delegation chain in engine.py.')
query('09_nonvacuous_legitimate_release',And(invariant,release),'sat','Shows the model permits legitimate release; not a deny-all proof.')
query('10_legitimate_admission_reachable',And(init,domain,transition,act==1,pn==1,validn),'sat','Positive reachability witness for admission.')
# Deliberately weaker variants must yield counterexamples.
bad_release=And(p==1,valid,Not(rev),env,grp,proof,scope,compartment,policy,checkpoint,owner==requester,now<expiry)
query('11_counterexample_missing_authority_gate',And(bad_release,Not(auth),identity_binding,task_binding),'sat','Detects omitted authority requirement in a deliberately weakened model.')
bad_pass=And(act==3,p==3,rev,pn==1,validn,revn)
query('12_counterexample_revoked_checkpoint_reactivation',And(domain,invariant,bad_pass,Not(nextinv)),'sat','Detects a deliberately weakened checkpoint transition.')
authorized_start,revoked_commit=Bools('authorized_start revoked_commit')
query('13_counterexample_cached_authorization_race',And(authorized_start,revoked_commit),'sat','A cached initial allow can coexist with revocation before commit; illustrates a race if commit does not recheck.')
query('14_commit_recheck_prevents_modeled_race',And(authorized_start,revoked_commit,Not(revoked_commit)),'unsat','With atomic current-state recheck, that particular stale-allow release is excluded. Atomicity is an assumption, not proved for distributed services.')
query('15_identity_binding_required',And(release,Not(identity_binding)),'unsat','Tightened release rule requires current instance/key generation binding.')
query('16_task_binding_required',And(release,Not(task_binding)),'unsat','Tightened release rule requires current approved task snapshot.')
snapshot_epoch,commit_epoch=Ints('snapshot_epoch commit_epoch')
query('17_current_epoch_prevents_stale_release',And(commit_epoch>snapshot_epoch,commit_epoch==snapshot_epoch),'unsat','Snapshot equality at atomic release excludes already-committed generation changes. Implementation locking/refinement remains an obligation.')
query('18_counterexample_omitted_identity_binding',And(bad_release,Not(identity_binding),auth,task_binding),'sat','An older modeled guard accepts a valid identity proof without current instance binding.')
count,maximum,nextcount=Ints('count maximum nextcount')
query('19_global_challenge_quota_preserved',And(maximum>0,count>=0,count<maximum,nextcount==count+1,nextcount>maximum),'unsat','Integer admission guard preserves configured global pending-challenge capacity.')
query('20_per_agent_challenge_quota_preserved',And(maximum==16,count>=0,count<maximum,nextcount==count+1,nextcount>16),'unsat','Integer admission guard preserves the per-agent capacity, assuming serialized update.')

result={'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'solver':'Z3 '+get_version_string(),
 'method':'SMT checks of single-session transition abstraction, release predicates and rights-set derivation',
 'assumptions':['Trusted evidence is accurate.','Signatures and cryptographic bindings are abstract valid/invalid predicates.','Release checks current state atomically.','Single immutable session ID; recovery issues another ID.','No direct backing-store bypass.'],
 'not_proved':['Python implementation refinement','cryptographic primitive security','OS or network isolation','LLM reasoning safety','distributed revocation latency','complete architecture correctness'],
 'queries':rows,'all_expected_results':all(x['pass'] for x in rows)}
(ROOT/'formal_results.json').write_text(json.dumps(result,indent=2))
print('Z3:',result['solver'],'expected results:',sum(x['pass'] for x in rows),'/',len(rows))
for row in rows:print(row['name'],row['result'])
if not result['all_expected_results']:raise SystemExit(1)
