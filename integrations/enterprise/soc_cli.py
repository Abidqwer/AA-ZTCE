#!/usr/bin/env python3
"""Initialize credentials, attach a SOC config, export ECS, or execute a signed action."""
import argparse
import json
from pathlib import Path
import sqlite3
import uuid
from soc.setup import initialize
from soc.client import request
from soc.ecs import to_ecs


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--directory',default='soc_state')
    sink=sub.add_parser('add-sink');sink.add_argument('--directory',default='soc_state')
    sink.add_argument('--id',required=True);sink.add_argument('--type',required=True,choices=['json_webhook','splunk_hec','elastic_bulk','syslog_tls'])
    sink.add_argument('--url');sink.add_argument('--host');sink.add_argument('--port',type=int,default=6514)
    sink.add_argument('--token-env');sink.add_argument('--ca-file');sink.add_argument('--index')
    attach=sub.add_parser('attach');attach.add_argument('--gateway-config',required=True)
    attach.add_argument('--directory',default='soc_state')
    export=sub.add_parser('export');export.add_argument('--database',required=True);export.add_argument('--output',required=True)
    action=sub.add_parser('action');action.add_argument('--url',required=True);action.add_argument('--directory',default='soc_state')
    action.add_argument('--action',required=True,choices=['revoke_session','suspend_session','require_reauth','disable_agent'])
    action.add_argument('--agent',required=True);action.add_argument('--session');action.add_argument('--case',required=True)
    action.add_argument('--command-id',default=None)
    args=p.parse_args()
    if args.command=='add-sink':
        config=initialize(args.directory)
        item={'id':args.id,'type':args.type}
        if args.type=='syslog_tls':
            if not args.host:p.error('--host required for syslog_tls')
            item.update(host=args.host,port=args.port)
        else:
            if not args.url:p.error('--url required for HTTP sinks')
            item['url']=args.url
        for key,value in [('token_env',args.token_env),('ca_file',args.ca_file),('index',args.index)]:
            if value:item[key]=value
        config['siem_sinks']=[s for s in config['siem_sinks'] if s['id']!=args.id]+[item]
        path=Path(args.directory).resolve()/'soc-config.json';path.write_text(json.dumps(config,indent=2));path.chmod(0o600)
        print(json.dumps({'configured_sink':args.id,'restart_required':True}))
    elif args.command in ('init','attach'):
        config=initialize(args.directory)
        if args.command=='attach':
            path=Path(args.gateway_config);gateway=json.loads(path.read_text());gateway['soc']=config
            path.write_text(json.dumps(gateway,indent=2));path.chmod(0o600)
        print(json.dumps({'config':str(Path(args.directory).resolve()/'soc-config.json'),'status':'ready'}))
    elif args.command=='export':
        db=sqlite3.connect('file:'+str(Path(args.database).resolve())+'?mode=ro',uri=True)
        with open(args.output,'w') as f:
            for seq,payload,digest in db.execute('SELECT seq,payload,event_hash FROM events ORDER BY seq'):
                event=json.loads(payload);event.update(sequence=seq,event_hash=digest)
                f.write(json.dumps(to_ecs(event))+'\n')
        db.close()
    else:
        root=Path(args.directory).resolve();config=json.loads((root/'soc-config.json').read_text())
        client=config['soar']['clients'][0];secret=Path(client['key_file']).read_text().strip()
        body={'action':args.action,'agent_id':args.agent,'case_id':args.case,'command_id':args.command_id or str(uuid.uuid4())}
        if args.session:body['session_id']=args.session
        status,result=request(args.url,client['id'],secret,'POST','/v1/actions',body,ca_file=config['soar']['cert_file'],
                              cert_file=config['soar']['cert_file'],key_file=config['soar']['key_file'])
        print(json.dumps({'http_status':status,'response':result},indent=2))
        if status!=200:raise SystemExit(1)


if __name__=='__main__':main()
