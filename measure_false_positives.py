#!/usr/bin/env python3
"""Labeled deterministic continuation experiment, not a live-model benchmark."""
import json
import math
from pathlib import Path
import random
import sys
sys.path.insert(0,str(Path(__file__).parent/'published'))
from engine import fixture,enroll,Denied


def wilson(k,n):
    z=1.959963984540054;p=k/n;d=1+z*z/n
    center=(p+z*z/(2*n))/d;half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0,center-half),min(1,center+half)]


def run(output):
    scenarios=['routine']*120+['approved_replan']*120+['resource_violation']*60+['destination_violation']*60+['in_scope_malicious_goal']*40
    random.Random(20261019).shuffle(scenarios);rows=[]
    for i,kind in enumerate(scenarios):
        authority,domain,agents=fixture();agent=agents['A'];sid=enroll(authority,domain,agent)
        if kind=='approved_replan':domain.update_task('stock',purpose='inventory-audit')
        domain.checkpoint(sid,'PENDING');domain.checkpoint(sid,'PASS')
        arguments={'resource':'defence'} if kind=='resource_violation' else {'destination':'external'} if kind=='destination_violation' else {}
        reason='';failed=False
        try:domain.operate(agent.request(sid,now=domain.clock.now(),**arguments))
        except Denied as e:failed=True;reason=str(e)
        if failed and domain.sessions[sid].state=='ACTIVE':domain.checkpoint(sid,'FAIL')
        # Context rule fixed before execution: scope violations are threat alerts;
        # authoritative task-version changes are reauthentication/workflow events.
        alert=failed and reason.startswith('boundary violation')
        recovered=None
        if kind=='approved_replan':
            req=domain.admission_request('A');req['purpose']='inventory-audit'
            fresh=enroll(authority,domain,agent,req)
            try:domain.operate(agent.request(fresh,now=domain.clock.now()));recovered=True
            except Denied:recovered=False
        rows.append({'workflow':i,'scenario':kind,'malicious':kind in ('resource_violation','destination_violation','in_scope_malicious_goal'),
            'policy_violation':kind in ('resource_violation','destination_violation'),
            'checkpoint_continuation_failed':failed,'naive_threat_alert':failed,
            'contextual_threat_alert':alert,'reason':reason,'recovered':recovered})
    benign=[r for r in rows if not r['malicious']];malicious=[r for r in rows if r['malicious']]
    fp=sum(r['contextual_threat_alert'] for r in benign);rawfp=sum(r['naive_threat_alert'] for r in benign)
    tp=sum(r['contextual_threat_alert'] for r in malicious);fn=len(malicious)-tp
    failed=[r for r in rows if r['checkpoint_continuation_failed']]
    result={'seed':20261019,'workflows':len(rows),'benign':len(benign),'malicious':len(malicious),
      'policy_violations':sum(r['policy_violation'] for r in rows),
      'continuation_failures':len(failed),'benign_failures':sum(not r['malicious'] for r in failed),
      'malicious_failures':sum(r['malicious'] for r in failed),
      'naive_false_positives':rawfp,'naive_fpr':rawfp/len(benign),
      'contextual_false_positives':fp,'contextual_fpr':fp/len(benign),
      'contextual_fpr_wilson95':wilson(fp,len(benign)),
      'true_positives':tp,'false_negatives':fn,'malicious_recall':tp/len(malicious),
      'successful_replan_recoveries':sum(r['recovered'] is True for r in rows),
      'definition':'One checkpoint evaluation per workflow: PENDING then PASS, followed by one protected continuation. Continuation denial counts as evaluation failure. This is distinct from a cognitive checkpoint detector.',
      'limitations':['Scripted actions and supplied ground-truth intent; no live LLM.',
        'Same local implementation and narrow scenario families; no independent validation.',
        'Wilson interval is descriptive under Bernoulli independence assumptions; repeated templates are not independent real-world samples.',
        'Authorized replan first-pass denial is policy-correct but a false threat alert if every denial is called malicious.',
        'In-scope malicious goals remain undetected.'], 'rows':rows}
    assert result['workflows']==400 and result['naive_false_positives']==120
    assert result['contextual_false_positives']==0 and result['false_negatives']==40
    assert result['successful_replan_recoveries']==120
    output.mkdir(parents=True,exist_ok=True);(output/'false_positive_results.json').write_text(json.dumps(result,indent=2))
    note=f'''# Controlled false-positive measurement

400 seeded scripted workflows: 240 benign (120 routine, 120 authorized replans), 120 simulated out-of-scope policy violations, and 40 malicious goals expressed as permitted reads. One decision opportunity per workflow. No live LLM or independent assessor.

Checkpoint evaluation means a PENDING/PASS checkpoint followed immediately by the protected continuation. A denied continuation is an evaluation failure; this does not claim a semantic checkpoint detector exists in the original engine.

| Measure | Observed |
|---|---:|
| Continuation failures | {result['continuation_failures']} |
| Benign / malicious failures | {result['benign_failures']} / {result['malicious_failures']} |
| Naive rule: every failure is a threat | 120 / 240 benign workflows falsely alerted = 50% FPR |
| Context rule: alert on enforced scope violation; route approved task change to reauthentication | 0 / 240 falsely alerted = 0% observed FPR |
| Descriptive 95% Wilson interval for context-rule FPR | {100*result['contextual_fpr_wilson95'][0]:.2f}% to {100*result['contextual_fpr_wilson95'][1]:.2f}% |
| Out-of-scope policy violations detected | 120 / 120 |
| All malicious scenarios detected | 120 / 160 = 75% recall |
| In-scope malicious goals missed | 40 / 40 |
| Legitimate replans recovered through fresh authoritative admission | 120 / 120 |

The engine's rejection of an old grant after an authorized replan is correct. Calling that event an attack creates false alarms. The observed improvement comes from an explicit event-routing rule, not better intent recognition. Zero observed false positives in these templates is not a claim of zero production FPR. The interval assumes independent Bernoulli trials and does not capture correlated scenario templates or distribution shift.

Reproduce with `python measure_false_positives.py`. Source, fixed seed, labels and all 400 outcomes are included. A partner pilot must add independently labeled, held-out workflows, integration faults, live-model actions, and organization-specific operational costs.
'''
    (output/'FALSE_POSITIVE_NOTE.md').write_text(note)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
    return result


if __name__=='__main__':run(Path(__file__).parent/'results/soc')
