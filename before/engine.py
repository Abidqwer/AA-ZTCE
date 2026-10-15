"""AA-ZTCE local policy/cryptographic reference harness. NOT a production service.
Environment evidence is supplied by a simulated trusted verifier; no OS sandbox
or LLM is instantiated. See README and generated report for assurance boundaries.
"""
import base64
import copy
import hashlib
import json
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def b64(value):
    return base64.b64encode(value).decode('ascii')


def unb64(value):
    return base64.b64decode(value, validate=True)


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def digest(value):
    return hashlib.sha256(canon(value)).hexdigest()


def derive(secret, sid):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sid.encode(), info=b'AA-ZTCE-test-session-v1').derive(secret)


class Denied(Exception):
    pass


class Clock:
    """Injectable clock: expiry tests advance this clock, not wall-clock sleep."""
    def __init__(self):
        self.value = 1000.0
    def now(self):
        return self.value
    def advance(self, seconds):
        self.value += seconds


class Authority:
    def __init__(self):
        self._key = ed25519.Ed25519PrivateKey.generate()
    @property
    def verifier(self):
        return self._key.public_key()
    def approve(self, request, expires):
        body = {'request': digest(request), 'expires': expires,
                'approval_id': str(uuid.uuid4()), 'authority_level': 2}
        return {'body': body, 'signature': b64(self._key.sign(canon(body)))}


class Agent:
    def __init__(self, name):
        self.name = name
        self._sign = ed25519.Ed25519PrivateKey.generate()
        self._exchange = x25519.X25519PrivateKey.generate()
        self.channels = {}
    @property
    def signing_public(self):
        return self._sign.public_key()
    @property
    def exchange_public(self):
        return public(self._exchange)
    def sign_admission(self, request, challenge):
        return b64(self._sign.sign(canon({'request': request, 'challenge': challenge})))
    def accept(self, response, domain_verifier):
        body = response['grant']
        domain_verifier.verify(unb64(response['signature']), canon(body))
        if body['agent'] != self.name:
            raise Denied('grant recipient mismatch')
        shared = self._exchange.exchange(x25519.X25519PublicKey.from_public_bytes(unb64(body['server_public'])))
        self.channels[body['sid']] = derive(shared, body['sid'])
        return body['sid']
    def request(self, sid, resource='inventory', destination='internal', action='read', now=1000.0):
        body = {'sid': sid, 'agent': self.name, 'resource': resource,
                'destination': destination, 'action': action,
                'request_id': str(uuid.uuid4()), 'at': now, 'audience': 'Domain-X'}
        return {'body': body, 'signature': b64(self._sign.sign(canon(body)))}
    def decrypt(self, envelope):
        return AESGCM(self.channels[envelope['sid']]).decrypt(
            unb64(envelope['nonce']), unb64(envelope['ciphertext']), canon(envelope['aad']))


@dataclass
class Session:
    grant: dict
    key: bytes
    request_ids: set = field(default_factory=set)
    state: str = 'ACTIVE'
    checkpoint: str = 'PASS'


class Domain:
    def __init__(self, authority, clock=None):
        self.clock = clock or Clock()
        self.authority = authority.verifier
        self._sign = ed25519.Ed25519PrivateKey.generate()
        self.identities = {}
        self.environments = {}
        self.tasks = {}
        self.groups = {}
        self.challenges = {}
        self.approvals_used = set()
        self.sessions = {}
        self.events = []
        self.policy_version = 1
        self.verifier_available = True
        self.objects = {'inventory': (2, {'retail'}, b'SYNTHETIC inventory: branch total=125'),
                        'defence': (4, {'defence'}, b'SYNTHETIC restricted dataset'),
                        'names': (2, {'hr'}, b'SYNTHETIC employee names'),
                        'addresses': (2, {'hr'}, b'SYNTHETIC employee addresses')}
        self.lock = threading.RLock()
        self.release_count = 0
    @property
    def verifier(self):
        return self._sign.public_key()
    def register(self, agent, clearance=2, compartments=('retail',)):
        # Trusted enrollment authority supplies these, never the requesting agent.
        self.identities[agent.name] = {'sign': agent.signing_public,
            'exchange': agent.exchange_public, 'clearance': clearance,
            'compartments': set(compartments), 'enabled': True}
        self.environments[agent.name] = {'version': 1, 'isolation': True,
            'paths': {'internal'}, 'expires': self.clock.now()+300}
    def configure_task(self, task_id, agents, resources=('inventory',), destinations=('internal',)):
        self.tasks[task_id] = {'agents': set(agents), 'resources': set(resources),
            'destinations': set(destinations), 'purpose': 'inventory-analysis'}
        self.groups[task_id] = {'members': set(agents), 'version': 1,
            'assessment': 'PASS'}
    def admission_request(self, agent, task_id='stock', resources=('inventory',), destinations=('internal',)):
        return {'agent': agent, 'task': task_id, 'resources': sorted(resources),
            'destinations': sorted(destinations), 'purpose': 'inventory-analysis',
            'audience': 'Domain-X', 'client_nonce': secrets.token_hex(16)}
    def challenge(self, request):
        with self.lock:
            nonce = secrets.token_hex(32)
            self.challenges[nonce] = (digest(request), self.clock.now()+10)
            return nonce
    def _deny(self, reason, **context):
        self.events.append({'time': self.clock.now(), 'event': 'DENY', 'reason': reason, **context})
        raise Denied(reason)
    def _environment_ok(self, agent, destinations):
        env = self.environments[agent]
        return (self.verifier_available and env['isolation'] is True
            and env['expires'] > self.clock.now()
            and set(destinations) <= env['paths']
            and env['paths'] <= set(destinations))
    def _resource_ok(self, identity, resource):
        if resource not in self.objects:
            return False
        level, compartments, _ = self.objects[resource]
        return level <= identity['clearance'] and compartments <= identity['compartments']
    def admit(self, request, challenge, proof, approval):
        with self.lock:
            entry = self.challenges.pop(challenge, None)
            if not entry or entry[0] != digest(request) or entry[1] <= self.clock.now():
                self._deny('invalid or expired admission challenge')
            identity = self.identities.get(request.get('agent'))
            if not identity or not identity['enabled']:
                self._deny('unknown or disabled identity')
            try:
                identity['sign'].verify(unb64(proof), canon({'request': request, 'challenge': challenge}))
            except (InvalidSignature, ValueError, TypeError):
                self._deny('invalid instance proof')
            task = self.tasks.get(request.get('task'))
            if not task or request['agent'] not in task['agents'] or request['purpose'] != task['purpose'] or request['audience'] != 'Domain-X':
                self._deny('unapproved task or purpose')
            if not request['resources'] or not set(request['resources']) <= task['resources'] or not set(request['destinations']) <= task['destinations']:
                self._deny('scope exceeds task')
            if any(not self._resource_ok(identity, r) for r in request['resources']):
                self._deny('clearance or compartment failed')
            group = self.groups[request['task']]
            if group['assessment'] != 'PASS' or request['agent'] not in group['members']:
                self._deny('collective assessment failed')
            if not self._environment_ok(request['agent'], request['destinations']):
                self._deny('critical environment check failed')
            if not approval:
                self._deny('authority approval missing')
            try:
                self.authority.verify(unb64(approval['signature']), canon(approval['body']))
            except (InvalidSignature, ValueError, TypeError, KeyError):
                self._deny('authority signature invalid')
            ab = approval['body']
            if (ab['request'] != digest(request) or ab['expires'] <= self.clock.now()
                or ab['authority_level'] < 2 or ab['approval_id'] in self.approvals_used):
                self._deny('authority binding, freshness or reuse failed')
            self.approvals_used.add(ab['approval_id'])
            sid = str(uuid.uuid4())
            ephemeral = x25519.X25519PrivateKey.generate()
            server_public = b64(public(ephemeral))
            key = derive(ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(identity['exchange'])), sid)
            grant = {'sid': sid, 'agent': request['agent'], 'task': request['task'],
                'purpose': request['purpose'], 'resources': request['resources'][:],
                'destinations': request['destinations'][:], 'expires': self.clock.now()+60,
                'env_version': self.environments[request['agent']]['version'],
                'group_version': group['version'], 'policy_version': self.policy_version,
                'server_public': server_public}
            self.sessions[sid] = Session(copy.deepcopy(grant), key)
            self.events.append({'time': self.clock.now(), 'event': 'GRANT', 'sid': sid, 'agent': request['agent']})
            return {'grant': grant, 'signature': b64(self._sign.sign(canon(grant))), 'server_public': server_public}
    def operate(self, signed):
        with self.lock:
            body = signed['body'];sid = body.get('sid')
            session = self.sessions.get(sid)
            if not session:
                self._deny('unknown session')
            grant = session.grant
            if body.get('agent') != grant['agent']:
                self._deny('session belongs to another agent')
            identity = self.identities[grant['agent']]
            try:
                identity['sign'].verify(unb64(signed['signature']), canon(body))
            except (InvalidSignature, ValueError, TypeError):
                self._deny('request signature invalid')
            if not identity['enabled'] or session.state != 'ACTIVE':
                self._deny('session or identity inactive')
            if session.checkpoint != 'PASS':
                self._deny('checkpoint pending or failed')
            if grant['expires'] <= self.clock.now():
                self._deny('session expired')
            if grant['policy_version'] != self.policy_version:
                self._deny('policy changed')
            if abs(body['at'] - self.clock.now()) > 5 or body['audience'] != 'Domain-X':
                self._deny('request freshness or audience failed')
            if body['request_id'] in session.request_ids:
                self._deny('request replay')
            session.request_ids.add(body['request_id'])
            group = self.groups[grant['task']]
            task = self.tasks[grant['task']]
            if (group['version'] != grant['group_version'] or group['assessment'] != 'PASS'
                or grant['agent'] not in group['members'] or grant['agent'] not in task['agents']):
                self._deny('group changed or failed')
            if (self.environments[grant['agent']]['version'] != grant['env_version']
                or not self._environment_ok(grant['agent'], grant['destinations'])):
                self._deny('environment changed, stale or unavailable')
            if (body['action'] != 'read' or body['resource'] not in grant['resources']
                or body['resource'] not in task['resources']
                or body['destination'] not in grant['destinations']
                or body['destination'] not in task['destinations']
                or not self._resource_ok(identity, body['resource'])):
                session.state = 'REVOKED'
                self._deny('boundary violation: session revoked')
            # Authorization and release are serialized under one process lock.
            aad = {'sid': sid, 'resource': body['resource'], 'request_id': body['request_id'],
                   'destination': body['destination']}
            nonce = secrets.token_bytes(12)
            plaintext = self.objects[body['resource']][2]
            envelope = {'sid': sid, 'aad': aad, 'nonce': b64(nonce),
                'ciphertext': b64(AESGCM(session.key).encrypt(nonce, plaintext, canon(aad)))}
            self.release_count += 1
            self.events.append({'time': self.clock.now(), 'event': 'RELEASE', 'sid': sid,
                'resource': body['resource'], 'request_id': body['request_id']})
            return envelope
    def change_environment(self, agent, paths=None, isolation=None):
        with self.lock:
            env = self.environments[agent];env['version'] += 1
            if paths is not None: env['paths'] = set(paths)
            if isolation is not None: env['isolation'] = isolation
    def change_group(self, task, members):
        with self.lock:
            self.groups[task]['members'] = set(members)
            self.groups[task]['version'] += 1
    def revoke(self, sid, reason='manual'):
        with self.lock:
            self.sessions[sid].state = 'REVOKED'
            self.events.append({'time': self.clock.now(), 'event': 'REVOKE', 'sid': sid, 'reason': reason})
    def disconnect(self, sid):
        self.revoke(sid, 'strict continuity break')
    def checkpoint(self, sid, verdict):
        if verdict not in {'PASS','PENDING','FAIL'}:
            raise ValueError('unknown checkpoint verdict')
        with self.lock:
            s=self.sessions[sid]
            if s.state != 'ACTIVE':
                self._deny('checkpoint cannot reactivate revoked session')
            s.checkpoint=verdict
            if verdict=='FAIL':s.state='REVOKED'


def fixture():
    authority=Authority();domain=Domain(authority)
    agents={name: Agent(name) for name in 'ABCD'}
    for agent in agents.values(): domain.register(agent)
    domain.configure_task('stock',agents)
    return authority,domain,agents


def enroll(authority,domain,agent,request=None):
    req = request or domain.admission_request(agent.name)
    nonce = domain.challenge(req)
    approval = authority.approve(req,domain.clock.now()+20)
    response = domain.admit(req,nonce,agent.sign_admission(req,nonce),approval)
    return agent.accept(response,domain.verifier)
