"""Attach SOC event/response capabilities without changing the published core."""
from pathlib import Path
import threading
from .events import Journal,EngineEvents,reason_code
from .siem import Exporter
from .soar import SOAR


class Bridge:
    def __init__(self,domain,config):
        self.domain=domain;self.local=threading.local()
        sinks=config.get('siem_sinks',[])
        ids=[s['id'] for s in sinks]
        if len(set(ids))!=len(ids):raise ValueError('duplicate sink IDs')
        self.journal=Journal(Path(config['state_dir'])/'soc.sqlite',
            config.get('domain_id','Domain-X'),ids,config.get('max_events',100000))
        self.events=EngineEvents(domain,self.journal);domain.events=self.events
        self.exporter=Exporter(self.journal,sinks)
        self.soar=SOAR(domain,self.journal,config['soar'])
        self.journal.append('integration.started',outcome='success',severity=2)
        self.exporter.start();self.soar.start()
    def begin_request(self,principal,message):
        self.events.context.principal=principal
        self.events.context.sid=None
        self.events.context.denied=False
        signed=message.get('signed')
        if isinstance(signed,dict) and isinstance(signed.get('body'),dict):
            sid=signed['body'].get('sid');session=self.domain.sessions.get(sid) if isinstance(sid,str) else None
            if session and session.grant['agent']==principal:self.events.context.sid=sid
    def denial(self,principal,error):
        if not getattr(self.events.context,'denied',False):
            self.journal.append('decision.denied',agent_id=principal if principal!='@admin' else None,
                session_id=getattr(self.events.context,'sid',None),outcome='denied',
                reason_code=reason_code(error),severity=7)
    def admin_event(self,method,args):
        kinds={'checkpoint':'checkpoint.'+str(args.get('verdict','')).lower(),
               'register':'identity.changed','set_identity_enabled':'identity.changed',
               'update_task':'task.changed','update_policy':'policy.changed',
               'change_environment':'environment.changed','change_group':'workflow.changed'}
        if method in kinds:
            sid=args.get('sid');session=self.domain.sessions.get(sid) if sid else None
            self.journal.append(kinds[method],session_id=sid,
                agent_id=args.get('agent') or args.get('name') or (session.grant['agent'] if session else None),
                task_id=args.get('task_id') or args.get('task'),actor_id='gateway-admin',
                policy_version=self.domain.policy_version,outcome='success',severity=5)
    def close(self):
        self.soar.close();self.exporter.close();self.journal.close()
