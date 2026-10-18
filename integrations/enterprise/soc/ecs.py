"""ECS 8.17-compatible event projection with namespaced AA-ZTCE extensions."""
from datetime import datetime,timezone


def to_ecs(raw):
    kind=raw['event_type'];denied=kind=='decision.denied';failed=kind in ('checkpoint.fail','checkpoint.failed')
    event={'id':raw['event_id'],'module':'aa_ztce','dataset':'aa_ztce.security',
           'provider':'AA-ZTCE','kind':'event','action':kind,
           'category':['iam'] if kind.startswith('identity.') else ['api'] if kind.startswith('soar.') else ['session'],
           'type':['denied'] if denied else ['change'] if kind.startswith(('identity.','checkpoint.','session.revoked','soar.')) else ['info'],
           'severity':raw.get('severity',3),
           'outcome':'failure' if denied or failed or raw.get('outcome')=='denied' else raw.get('outcome','success')}
    if event['outcome'] not in ('success','failure','unknown'):event['outcome']='unknown'
    if raw.get('reason_code'):event['reason']=raw['reason_code']
    if 'sequence' in raw:event['sequence']=raw['sequence']
    if raw.get('event_hash'):event['hash']=raw['event_hash']
    result={'@timestamp':datetime.fromtimestamp(raw['timestamp'],timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
        'ecs':{'version':'8.17.0'},'event':event,'service':{'name':'aa-ztce','type':'agent-access-control'},
        'observer':{'name':raw['domain_id'],'product':'AA-ZTCE','vendor':'AA-ZTCE'},
        'aa_ztce':{k:v for k,v in raw.items() if k not in ('timestamp','event_type','event_id','severity')}}
    if raw.get('agent_id'):
        result['user']={'id':raw['agent_id']};result['related']={'user':[raw['agent_id']]}
    return result
