"""Authenticated desired-state workflow API; never issues grants or identities.

SQLite stores desired definitions. Startup reapplies them to the local domain.
Revision CAS prevents stale Terraform clients overwriting concurrent changes.
The gateway's built-in workflows cannot be modified through this interface.
"""
import json
import re


class WorkflowError(Exception):
    def __init__(self, status, message): self.status=status; self.message=message


class Workflows:
    def __init__(self, domain, journal):
        self.domain=domain; self.journal=journal
        with journal.lock, journal.db:
            journal.db.execute('CREATE TABLE IF NOT EXISTS workflows(id TEXT PRIMARY KEY, definition TEXT NOT NULL, revision INTEGER NOT NULL)')
        with domain.lock, journal.lock:
            self.reserved=set(domain.tasks)
            rows=journal.db.execute('SELECT id,definition FROM workflows').fetchall()
            for name, definition in rows:
                self.apply(name, json.loads(definition))

    def apply(self, name, definition):
        d=self.domain
        # Desired definitions reference pre-existing identities and resources only.
        if not set(definition['agents']) <= set(d.identities):
            raise ValueError('persisted workflow references unavailable identities')
        if not set(definition['resources']) <= set(d.objects):
            raise ValueError('persisted workflow references unavailable resources')
        d.configure_task(name, definition['agents'], definition['resources'], definition['destinations'])
        d.update_task(name, purpose=definition['purpose'])

    def handle(self, client, method, name, body=None):
        if 'manage_workflows' not in client['actions']:
            raise WorkflowError(403, 'workflow administration scope denied')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name) or name in self.reserved:
            raise WorkflowError(400, 'invalid or reserved workflow ID')
        allowed_agents=set(client.get('agents', []))
        with self.domain.lock, self.journal.lock:
            row=self.journal.db.execute('SELECT definition,revision FROM workflows WHERE id=?',(name,)).fetchone()
            old=json.loads(row[0]) if row else None
            if old and '*' not in allowed_agents and not set(old['agents']) <= allowed_agents:
                raise WorkflowError(403, 'workflow target scope denied')
            if method=='GET':
                if not row: raise WorkflowError(404, 'workflow not found')
                return {'id':name, **old, 'revision':row[1]}
            if type(body) is not dict or type(body.get('expected_revision')) is not int:
                raise WorkflowError(400, 'integer expected_revision required')
            revision=row[1] if row else 0
            if body['expected_revision'] != revision: raise WorkflowError(409, 'workflow revision changed')
            if method=='PUT':
                if set(body) != {'agents','resources','destinations','purpose','expected_revision'}:
                    raise WorkflowError(400, 'invalid workflow fields')
                definition={k:v for k,v in body.items() if k!='expected_revision'}
                for key in ('agents','resources','destinations'):
                    values=definition[key]
                    if type(values) is not list or not 1 <= len(values) <= 32 or any(type(v) is not str or not 1 <= len(v) <= 128 for v in values) or len(set(values))!=len(values):
                        raise WorkflowError(400, 'invalid workflow scope')
                    definition[key]=sorted(values)
                if type(definition['purpose']) is not str or not 1 <= len(definition['purpose']) <= 256:
                    raise WorkflowError(400, 'invalid workflow purpose')
                if '*' not in allowed_agents and not set(definition['agents']) <= allowed_agents:
                    raise WorkflowError(403, 'agent scope denied')
                if not set(definition['resources']) <= set(client.get('resources', [])) or not set(definition['destinations']) <= set(client.get('destinations', [])):
                    raise WorkflowError(403, 'resource or destination administration scope denied')
                if not set(definition['agents']) <= set(self.domain.identities) or not set(definition['resources']) <= set(self.domain.objects):
                    raise WorkflowError(400, 'identity or resource unavailable')
                if any(not self.domain._resource_ok(self.domain.identities[a], r) for a in definition['agents'] for r in definition['resources']):
                    raise WorkflowError(403, 'workflow exceeds enrolled identity authority')
                self.journal.append('workflow.definition.changed', actor_id=client['id'],task_id=name,severity=6)
                with self.journal.db:
                    self.journal.db.execute('INSERT OR REPLACE INTO workflows VALUES(?,?,?)',(name,json.dumps(definition),revision+1))
                self.apply(name,definition)
                return {'id':name, **definition, 'revision':revision+1}
            if method=='DELETE':
                if set(body)!={'expected_revision'}:raise WorkflowError(400,'invalid deletion fields')
                if not row: return {'id':name,'deleted':True}
                self.journal.append('workflow.definition.deleted',actor_id=client['id'],task_id=name,severity=6)
                # Invalidate grants before removing their referenced task/group.
                for sid, session in self.domain.sessions.items():
                    if session.grant['task']==name:self.domain.revoke(sid,'workflow deleted')
                with self.journal.db:self.journal.db.execute('DELETE FROM workflows WHERE id=?',(name,))
                self.domain.tasks.pop(name,None);self.domain.groups.pop(name,None)
                return {'id':name,'deleted':True}
            raise WorkflowError(405,'method unsupported')
