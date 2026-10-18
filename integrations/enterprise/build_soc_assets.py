#!/usr/bin/env python3
"""Generate the API contract, native Splunk dashboard and evidence-backed HTML dashboard."""
import html
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent


def _base_contract():
    id_schema={'type':'string','pattern':'^[A-Za-z0-9_.:@-]{1,128}$'}
    action={'type':'object','additionalProperties':False,'required':['action','agent_id','command_id','case_id'],
        'properties':{'action':{'type':'string','enum':['revoke_session','suspend_session','require_reauth','disable_agent']},
            **{key:id_schema for key in ('agent_id','session_id','command_id','case_id')}},
        'oneOf':[{'properties':{'action':{'enum':['revoke_session','suspend_session']}},'required':['session_id']},
                 {'properties':{'action':{'enum':['require_reauth','disable_agent']}},'not':{'required':['session_id']}}]}
    headers={'KeyId':'X-AA-Key-ID','Audience':'X-AA-Audience','Timestamp':'X-AA-Timestamp','Nonce':'X-AA-Nonce','Signature':'X-AA-Signature'}
    schemes={'ClientCertificate':{'type':'mutualTLS'}}
    schemes.update({k:{'type':'apiKey','in':'header','name':v} for k,v in headers.items()})
    security=[{k:[] for k in schemes}]
    errors={str(code):{'description':desc,'content':{'application/json':{'schema':{'$ref':'#/components/schemas/Error'}}}}
            for code,desc in [(400,'Invalid request'),(401,'Authentication failed or stale timestamp'),(403,'Action/target scope denied'),
                (404,'Unknown target or endpoint'),(409,'Nonce replay or command-ID conflict'),(413,'Body too large'),
                (503,'Audit or operation unavailable; retry with same command ID and new nonce')]}
    return {'openapi':'3.1.0','info':{'title':'AA-ZTCE SOAR Control API','version':'0.3.0',
        'description':'mTLS plus HMAC-SHA256 signed REST. Canonical signing string is METHOD + LF + exact path/query + LF + audience/domain ID + LF + integer timestamp + LF + nonce + LF + lowercase SHA256(exact UTF-8 body). No trailing newline. Nonce: 32-128 lowercase hexadecimal characters. Timestamp window: +/-90 seconds. Nonce retention: 180 seconds. New nonce for each retry; preserve command_id and exact semantic body. No credential or privilege issuance endpoints.'},
        'security':security,'paths':{
            '/health':{'get':{'security':[{'ClientCertificate':[]}],'summary':'Minimal liveness, without state or secrets','responses':{'200':{'description':'Service running'}}}},
            '/v1/actions':{'post':{'operationId':'applyResponse','summary':'Apply a scoped preventive response',
                'requestBody':{'required':True,'content':{'application/json':{'schema':{'$ref':'#/components/schemas/Action'}}}},
                'responses':{'200':{'description':'Applied, or identical completed command returned without reapplying',
                    'content':{'application/json':{'schema':{'$ref':'#/components/schemas/ActionResult'}}}},**errors}}},
            '/v1/events':{'get':{'operationId':'readEvents','summary':'Read agent-scoped ECS events',
                'parameters':[{'name':'after','in':'query','schema':{'type':'integer','minimum':0,'default':0}},
                              {'name':'limit','in':'query','schema':{'type':'integer','minimum':1,'maximum':500,'default':100}}],
                'responses':{'200':{'description':'ECS documents and global sequence cursor; skipped rows may be hidden by agent scope',
                    'content':{'application/json':{'schema':{'type':'object','required':['events','next_after'],
                        'properties':{'events':{'type':'array','items':{'type':'object','required':['@timestamp','ecs','event','aa_ztce']}},
                                      'next_after':{'type':'integer'}}}}}},**errors}}}},
        'components':{'securitySchemes':schemes,'schemas':{'Action':action,
            'ActionResult':{'type':'object','required':['command_id','action','agent_id','status','affected_sessions','duplicate'],
                'properties':{'command_id':id_schema,'action':{'type':'string'},'agent_id':id_schema,
                    'status':{'const':'applied'},'affected_sessions':{'type':'array','items':{'type':'string'}},'duplicate':{'type':'boolean'}}},
            'Error':{'type':'object','required':['error'],'properties':{'error':{'type':'string'}}}}}}


def contract():
    from enterprise.contract import extend
    return extend(_base_contract())


def main():
    docs=ROOT/'docs/soc';docs.mkdir(parents=True,exist_ok=True)
    (docs/'openapi.json').write_text(json.dumps(contract(),indent=2))
    template={'index_patterns':['aa-ztce-security*'],'template':{'mappings':{'properties':{
        '@timestamp':{'type':'date'},'ecs':{'properties':{'version':{'type':'keyword'}}},
        'event':{'properties':{k:{'type':'keyword'} for k in ('id','module','dataset','provider','kind','action','category','type','outcome','reason')}
            |{'severity':{'type':'long'},'sequence':{'type':'long'}}},
        'user':{'properties':{'id':{'type':'keyword'}}},'aa_ztce':{'type':'flattened'}}}}}
    (docs/'elastic-index-template.json').write_text(json.dumps(template,indent=2))
    (docs/'splunk-props.conf').write_text('[aa_ztce:security]\nKV_MODE = json\nSHOULD_LINEMERGE = false\nTRUNCATE = 65536\n')
    dashboard=ET.Element('dashboard',{'version':'1.1'});ET.SubElement(dashboard,'label').text='AA-ZTCE / SOC correlation'
    ET.SubElement(dashboard,'description').text='Preventive-control events and independent SOC telemetry; correlation is investigative context, not proof of causation.'
    queries=[('Event timeline','sourcetype=aa_ztce:security | timechart count by event.action'),
        ('Denied operations by reason','sourcetype=aa_ztce:security event.action="decision.denied" | stats count by event.reason user.id'),
        ('Agent correlation with EDR / identity telemetry','(sourcetype=aa_ztce:security OR event.dataset="soc.synthetic") | bin _time span=5m | stats values(event.dataset) AS datasets values(event.action) AS actions count by _time user.id | where mvcount(datasets)>1'),
        ('Response history','sourcetype=aa_ztce:security event.action="soar.action.completed" | table _time user.id aa_ztce.command_id aa_ztce.case_id aa_ztce.operation')]
    for title,query in queries:
        row=ET.SubElement(dashboard,'row');panel=ET.SubElement(row,'panel');ET.SubElement(panel,'title').text=title
        chart=ET.SubElement(panel,'table');search=ET.SubElement(chart,'search');ET.SubElement(search,'query').text=query
        ET.SubElement(search,'earliest').text='-24h';ET.SubElement(search,'latest').text='now'
    ET.ElementTree(dashboard).write(docs/'splunk-dashboard.xml',encoding='unicode')
    resultdir=ROOT/'results/soc';events=[json.loads(s) for s in (resultdir/'events.ecs.ndjson').read_text().splitlines() if s]
    events.sort(key=lambda e:e['@timestamp'])
    # Independent source type, synthetic event contents, joined by workload ID and time.
    first=next(e for e in events if e.get('user',{}).get('id')=='A')
    other=[{'@timestamp':first['@timestamp'],'ecs':{'version':'8.17.0'},
        'event':{'id':'synthetic-edr-001','dataset':'soc.synthetic','action':'edr.suspicious-process','category':['process'],'type':['start'],'kind':'event','outcome':'unknown'},
        'user':{'id':'A'},'message':'Synthetic EDR signal for dashboard correlation; no endpoint was investigated.'},
        {'@timestamp':first['@timestamp'],'ecs':{'version':'8.17.0'},
        'event':{'id':'synthetic-idp-001','dataset':'soc.synthetic','action':'identity.risk-change','category':['iam'],'type':['change'],'kind':'event','outcome':'unknown'},
        'user':{'id':'A'},'message':'Synthetic identity telemetry for correlation.'}]
    (resultdir/'soc_telemetry.synthetic.ecs.ndjson').write_text(''.join(json.dumps(e)+'\n' for e in other))
    from datetime import datetime
    def stamp(e):return datetime.fromisoformat(e['@timestamp'].replace('Z','+00:00')).timestamp()
    def correlations(e):return [s['event']['action'] for s in other if e.get('user',{}).get('id')==s['user']['id'] and abs(stamp(e)-stamp(s))<=300]
    matches=[{'aa_event_id':e['event']['id'],'user_id':e['user']['id'],'soc_signals':correlations(e)}
             for e in events if correlations(e)]
    (resultdir/'correlations.json').write_text(json.dumps({'window_seconds':300,'telemetry_is_synthetic':True,'matches':matches},indent=2))
    counts={}
    for e in events:counts[e['event']['action']]=counts.get(e['event']['action'],0)+1
    fp=json.loads((resultdir/'false_positive_results.json').read_text());metrics=json.loads((resultdir/'soar_latency.json').read_text())
    cards=''.join(f'<article><b>{value}</b><span>{label}</span></article>' for value,label in [
        (len(events),'Captured AA-ZTCE events'),(len(matches),'Shared-ID / 5-minute matches'),
        ('0 / 240','Context-rule false alerts (scripted)'),('40 / 40','In-scope malicious goals missed')])
    rows=''.join('<tr>'+''.join('<td>'+html.escape(str(value))+'</td>' for value in [e['@timestamp'],e.get('user',{}).get('id','—'),
        e['event']['action'],e['event'].get('reason',''),', '.join(correlations(e)) or '—'])+'</tr>' for e in events)
    payload=json.dumps(events).replace('<','\\u003c')
    page=r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AA-ZTCE / SOC correlation evidence</title><style>
:root{font:15px system-ui;color:#dce8f3;background:#071422}body{max-width:1320px;margin:0 auto;padding:36px}header{border-bottom:1px solid #2a4259;padding-bottom:24px}small{color:#7ce0cc;letter-spacing:2px}h1{font-size:36px;margin:12px 0}p{line-height:1.6;color:#afc3d5}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}article{background:#10283c;border:1px solid #25435d;padding:22px;border-radius:12px}article b{font-size:30px;display:block;color:#7ce0cc}article span{display:block;margin-top:12px;color:#afc3d5}input,select,button{background:#10283c;color:white;border:1px solid #3e647e;padding:12px;border-radius:6px;margin:0 8px 14px 0}.scroll{overflow:auto;max-height:650px;border:1px solid #25435d;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:13px;border-bottom:1px solid #25435d;vertical-align:top}th{position:sticky;top:0;background:#17354b}.notice{border-left:4px solid #eeb75e;padding:12px 20px;background:#1a2b38}footer{color:#95afc4;margin-top:24px}@media(max-width:750px){body{padding:20px}.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:27px}}
</style><header><small>AA-ZTCE · CONTROL / OBSERVABILITY</small><h1>SOC correlation evidence</h1><p>Actual local integration events, correlated with explicitly synthetic EDR and identity telemetry. No hosted SIEM or customer environment was connected.</p></header><section class="cards">CARDS</section><p class="notice">Matching workload IDs within five minutes supplies investigative context. It does not establish malicious intent or causation. The local policy study missed permitted reads serving malicious goals.</p><h2>Event timeline</h2><input id="q" aria-label="Filter events" placeholder="Filter by action, agent, reason or signal"><button id="download">Download captured ECS events</button><span id="count"></span><div class="scroll"><table><thead><tr><th>UTC timestamp</th><th>Workload ID</th><th>AA-ZTCE action</th><th>Reason code</th><th>Synthetic SOC correlation</th></tr></thead><tbody>ROWS</tbody></table></div><footer>Shared correlation key: user.id · Window: ±300 seconds · ECS 8.17 projection · Captured events and correlation JSON are bundled.</footer><script>const data=PAYLOAD;const rows=[...document.querySelectorAll('tbody tr')];function filter(){let n=0;for(const r of rows){r.hidden=!r.textContent.toLowerCase().includes(document.querySelector('#q').value.toLowerCase());if(!r.hidden)n++;}document.querySelector('#count').textContent=n+' events';}document.querySelector('#q').addEventListener('input',filter);document.querySelector('#download').onclick=()=>{const a=document.createElement('a');const u=URL.createObjectURL(new Blob([data.map(x=>JSON.stringify(x)).join('\n')+'\n'],{type:'application/x-ndjson'}));a.href=u;a.download='aa-ztce-events.ecs.ndjson';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};filter();</script></html>'''
    (docs/'SOC_Correlation_Dashboard.html').write_text(page.replace('CARDS',cards).replace('ROWS',rows).replace('PAYLOAD',payload))
    doc='''# Control interface and deployment contract

Profile: REST over TLS 1.2+ with mTLS and per-client HMAC-SHA256 signatures. The generated local sandbox enables mTLS. Local certificates/keys are development credentials, valid for 30 days; use a managed CA and separate server/client certificates for a real pilot. Keys are per deployment and client. No platform account was connected.

## Authentication and replay

Send X-AA-Key-ID, X-AA-Audience (the configured domain_id), X-AA-Timestamp (integer Unix seconds), X-AA-Nonce (32-128 lowercase hex), and X-AA-Signature (hex HMAC). Sign six lines, separated by LF with no trailing LF: METHOD; exact path including query; audience; timestamp; nonce; SHA256 of exact request bytes. For GET, hash the empty body. Timestamp tolerance is 90 seconds; nonces persist 180 seconds. Response identity is protected by verified TLS. Certificate trust does not grant an action: the HMAC client must also have that action and agent scope.

## Actions

POST /v1/actions requires command_id, case_id, action, agent_id, and session_id for session actions. revoke_session invalidates the named session. suspend_session sets PENDING and cannot reactivate a revoked session. require_reauth revokes every current session for the agent; it does not authenticate automatically. disable_agent disables identity and revokes current sessions. No action issues grants, credentials, or elevated permissions. Resume/re-enable requires the existing trusted administration/admission process.

## Retry and failure

Repeat a completed command with a NEW nonce and the same command_id/body to retrieve its result. A changed body with an old ID returns 409. Pending commands may be conservatively reapplied after interruption; all supported responses are monotone/idempotent containment operations. A successful response means the local gateway action completed, not that a remote queued tool action was canceled. Original sessions are in memory and do not survive a gateway restart. Audit/command records are durable; the system is not a distributed transaction.

## Event delivery

ECS projection: @timestamp, ecs.version, event.id/action/category/type/outcome/severity, observer.name, user.id and namespaced aa_ztce fields. SIEM exporters: Splunk HEC, Elasticsearch bulk, JSON HTTPS webhook, RFC 5424/5425 syslog over verified TLS. Local collectors validated protocol delivery; actual vendor instances were not available. HTTP acceptance is not proof of search indexing. Syslog TLS is write completion, not an application acknowledgment. Delivery is at least once; deduplicate event.id. The hash chain detects modifications when checked against a trusted head; an attacker controlling the host and replacing the whole chain is outside that guarantee. Archive and externally anchor the journal head.

## Capacity and time

The local audit journal stops accepting new events at max_events (default 100,000); event persistence failure prevents successful protected responses. SIEM outages retain the outbox and retry with bounded exponential delay. Monitor queue depth and provision retention/archival before the limit. Blocking audit writes can add access latency. Wall-clock integrity and clock jumps need operational controls. The SOAR API bounds concurrent request handlers at 32 and request bodies at 16 KiB. This is a tested integration candidate, not an independently audited production service.

## Latency

No contractual SLO is claimed. The local end-to-end mTLS/HMAC/action/SQLite measurements are in results/soc/soar_latency.json. A pilot acceptance target is p95 <= 1 second for local control acknowledgment under agreed load, with no successful protected continuation starting after the response ACK for a revoked session. Remote SIEM visibility and multi-host revocation need separate measured targets.

## Run without editing source

`bash run_soc.sh` installs missing Python dependencies and runs the entire local verification and asset-generation workflow. Linux/libseccomp is required for confined workers. `bash run_soc.sh serve --directory soc_state` starts a persistent synthetic sandbox, generates local credentials and prints its SOAR URL and initial session IDs. `bash run_soc.sh init --directory soc_state` initializes credentials only. `bash run_soc.sh add-sink` and `bash run_soc.sh attach` configure a chosen real endpoint and attach to an existing gateway configuration without source edits; use --help for their required arguments. Real SIEM endpoints, access tokens, trust roots, and approved deployment access are still required for a partner environment.

## Sources

- ECS event fields: https://www.elastic.co/docs/reference/ecs/ecs-event
- Splunk HEC event format: https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector
- Syslog: https://www.rfc-editor.org/rfc/rfc5424 and https://www.rfc-editor.org/rfc/rfc5425
'''
    (docs/'CONTROL_INTERFACE.md').write_text(doc)
    print(json.dumps({'assets':str(docs),'captured_events':len(events),'correlation_matches':len(matches),'soar_p95_ms':metrics['p95_ms']}))


if __name__=='__main__':main()
