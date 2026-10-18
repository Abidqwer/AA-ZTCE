"""Bounded local protocol abuse and legitimate request burst; no external targets."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import statistics
import time


def run(deployment,requests=400):
    sid=deployment.enroll('A')['sid'];worker=deployment.workers['A']
    prepared=worker.call('prepare',sid=sid)
    first=worker.rpc(op='operate',signed=prepared)
    if not first.get('ok'):raise RuntimeError('stress precondition: authorized operation failed')
    invalid=[None,{},[],{'body':{}}, {'body':prepared['body'],'signature':'not-base64'}]
    replay_denied=0;malformed_denied=0;principal_denied=0;signature_denied=0
    start=time.perf_counter()
    for i in range(requests):
        case=i%4
        if case==0:
            reply=worker.rpc(op='operate',signed=prepared);replay_denied+=not reply.get('ok')
        elif case==1:
            reply=worker.rpc(op='operate',signed=invalid[(i//4)%len(invalid)]);malformed_denied+=not reply.get('ok')
        elif case==2:
            admission=worker.call('admission_request');admission['agent']='B'
            reply=worker.rpc(op='challenge',request=admission);principal_denied+=not reply.get('ok')
        else:
            bad=worker.call('prepare',sid=sid);bad['signature']=prepared['signature']
            reply=worker.rpc(op='operate',signed=bad);signature_denied+=not reply.get('ok')
    abuse_seconds=time.perf_counter()-start
    sessions={name:deployment.enroll(name)['sid'] for name in 'ABCD'}
    latencies=[]
    def burst(name):
        allowed=0;lat=[]
        for _ in range(25):
            before=time.perf_counter();result=deployment.workers[name].call('operate',sid=sessions[name])
            lat.append((time.perf_counter()-before)*1000);allowed+=bool(result.get('ok'))
        return allowed,lat
    before=time.perf_counter()
    with ThreadPoolExecutor(4) as pool:answers=list(pool.map(burst,'ABCD'))
    for _,lat in answers:latencies.extend(lat)
    burst_seconds=time.perf_counter()-before
    return {'scripted_requests':requests,'replay_denied':int(replay_denied),'malformed_denied':int(malformed_denied),
        'principal_spoof_denied':int(principal_denied),'invalid_signature_denied':int(signature_denied),
        'all_scripted_abuse_denied':sum([replay_denied,malformed_denied,principal_denied,signature_denied])==requests,
        'abuse_seconds':abuse_seconds,'legitimate_burst_requests':100,'legitimate_burst_allowed':sum(a[0] for a in answers),
        'burst_seconds':burst_seconds,'burst_throughput_rps':100/burst_seconds,
        'burst_p95_ms':sorted(latencies)[int(.95*(len(latencies)-1))],
        'scope':'Scripted protocol exercise on this single-host full assurance profile; not model-generated exploits or a production capacity benchmark.'}
