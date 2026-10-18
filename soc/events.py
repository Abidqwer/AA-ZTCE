"""Durable bounded event journal, hash chain and transactional SIEM outbox."""
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def reason_code(reason):
    text=str(reason).lower()
    for fragment,code in [('task','task_changed'),('boundary','scope_violation'),('signature','invalid_signature'),
        ('replay','replay_detected'),('expired','expired'),('quota','quota_exceeded'),
        ('checkpoint','checkpoint_required'),('identity','identity_invalid'),
        ('group','workflow_changed'),('environment','environment_invalid'),
        ('policy','policy_changed'),('principal','principal_mismatch'),('schema','invalid_schema')]:
        if fragment in text:return code
    return 'policy_decision'


class Journal:
    def __init__(self,path,domain_id,sinks=(),max_events=100000):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(path.parent,0o700)
        self.path=path;self.domain_id=domain_id;self.max_events=max_events
        self.lock=threading.RLock();self.sinks=list(sinks);self.anchor_callback=None
        self.db=sqlite3.connect(path,check_same_thread=False,timeout=10)
        os.chmod(path,0o600)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,
          payload TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS deliveries(event_id TEXT,sink TEXT,attempts INTEGER DEFAULT 0,
          next_at REAL DEFAULT 0,status TEXT DEFAULT 'pending',last_error TEXT,
          PRIMARY KEY(event_id,sink));
        CREATE TABLE IF NOT EXISTS nonces(client_id TEXT,nonce TEXT,expires REAL,
          PRIMARY KEY(client_id,nonce));
        CREATE TABLE IF NOT EXISTS commands(client_id TEXT,command_id TEXT,body_hash TEXT,
          status TEXT,result TEXT,PRIMARY KEY(client_id,command_id));
        ''');self.db.commit()
    def append(self,event_type,**fields):
        # Strict allowlist: never persist complete requests, proofs, keys or plaintext.
        allowed={'agent_id','session_id','task_id','resource_id','operation','outcome',
                 'reason_code','actor_id','command_id','case_id','policy_version','severity','redaction_count'}
        event={'schema':'aa-ztce.security/1.0','event_id':str(uuid.uuid4()),
               'timestamp':time.time(),'domain_id':self.domain_id,'event_type':event_type}
        for k,v in fields.items():
            if k not in allowed or v is None:continue
            if k in ('severity','policy_version','redaction_count'):event[k]=int(v)
            elif isinstance(v,str):event[k]=v.replace('\n',' ').replace('\r',' ')[:160]
        event.setdefault('severity',3)
        event['correlation_id']=event.get('session_id') or event.get('task_id') or event['event_id']
        with self.lock,self.db:
            count=self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            if count>=self.max_events:raise RuntimeError('audit journal capacity exhausted')
            previous=self.db.execute('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
            previous=previous[0] if previous else '0'*64
            payload=canonical(event).decode();digest=hashlib.sha256(previous.encode()+payload.encode()).hexdigest()
            self.db.execute('INSERT INTO events(event_id,payload,previous_hash,event_hash) VALUES(?,?,?,?)',
                            (event['event_id'],payload,previous,digest))
            for sink in self.sinks:
                self.db.execute('INSERT INTO deliveries(event_id,sink) VALUES(?,?)',(event['event_id'],sink))
        if self.anchor_callback:self.anchor_callback(self)
        return event
    def read(self,after=0,limit=100):
        with self.lock:
            rows=self.db.execute('SELECT seq,payload,previous_hash,event_hash FROM events WHERE seq>? ORDER BY seq LIMIT ?',
                                 (after,min(max(limit,1),500))).fetchall()
        return [{'sequence':r[0],**json.loads(r[1]),'previous_hash':r[2],'event_hash':r[3]} for r in rows]
    def verify_chain(self):
        previous='0'*64;count=0
        with self.lock:
            for payload,prev,digest in self.db.execute('SELECT payload,previous_hash,event_hash FROM events ORDER BY seq'):
                if prev!=previous or hashlib.sha256(prev.encode()+payload.encode()).hexdigest()!=digest:
                    return {'valid':False,'checked':count}
                previous=digest;count+=1
        return {'valid':True,'checked':count,'head':previous}
    def due(self):
        with self.lock:
            return self.db.execute('''SELECT d.event_id,d.sink,e.payload,d.attempts FROM deliveries d
                JOIN events e USING(event_id) WHERE status='pending' AND next_at<=?
                ORDER BY e.seq LIMIT 100''',(time.time(),)).fetchall()
    def delivered(self,event_id,sink,error=None):
        with self.lock,self.db:
            if error:
                attempts=self.db.execute('SELECT attempts FROM deliveries WHERE event_id=? AND sink=?',
                                         (event_id,sink)).fetchone()[0]+1
                self.db.execute('UPDATE deliveries SET attempts=?,next_at=?,last_error=? WHERE event_id=? AND sink=?',
                    (attempts,time.time()+min(60,0.2*2**min(attempts,8)),type(error).__name__,event_id,sink))
            else:
                self.db.execute("UPDATE deliveries SET status='sent',last_error=NULL WHERE event_id=? AND sink=?",(event_id,sink))
    def pending(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM deliveries WHERE status='pending'").fetchone()[0]
    def close(self):
        with self.lock:self.db.close()


class EngineEvents:
    """Preserve the original in-memory event behavior while adding durable export."""
    def __init__(self,domain,journal):
        self.domain=domain;self.journal=journal;self.memory=deque(maxlen=8192)
        self.context=threading.local()
    def append(self,raw):
        kind={'GRANT':'session.granted','RELEASE':'resource.released',
              'REVOKE':'session.revoked','DENY':'decision.denied'}.get(raw.get('event'),'engine.event')
        sid=raw.get('sid') or getattr(self.context,'sid',None)
        session=self.domain.sessions.get(sid) if sid else None
        grant=session.grant if session else {}
        if kind=='decision.denied':self.context.denied=True
        self.journal.append(kind,session_id=sid,agent_id=raw.get('agent') or grant.get('agent') or getattr(self.context,'principal',None),
            task_id=grant.get('task'),resource_id=raw.get('resource'),
            outcome='denied' if kind=='decision.denied' else 'success',
            reason_code=reason_code(raw.get('reason','')),policy_version=self.domain.policy_version,
            severity=7 if kind=='decision.denied' else 4 if kind=='session.revoked' else 2)
        self.memory.append(raw)
    def __iter__(self):return iter(self.memory)
    def __len__(self):return len(self.memory)
