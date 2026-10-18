"""Local integration adapter. Original published engine.py is unchanged.

The hardened mode authenticates the connection principal and binds admission
requests to that principal. Baseline mode intentionally omits that binding to
reproduce the core's unauthenticated challenge-allocation assumption.
"""
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socketserver
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).parent / 'published'))
from runtime_engine import Authority, Domain, Denied, canon, unb64, b64
from cryptography.hazmat.primitives.asymmetric import ed25519

MAX_FRAME = 16384


class RealClock:
    def now(self):
        return time.time()


def main():
    config_path, requested_port, mode = sys.argv[1:]
    config = json.loads(Path(config_path).read_text())
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)
    authority = types.SimpleNamespace(verifier=ed25519.Ed25519PublicKey.from_public_bytes(
        unb64(config['authority_public'])))
    from enterprise.keys import provider_from_config
    domain = Domain(authority, RealClock(),key_provider=provider_from_config(config.get('signing',{})))
    def register(name, pub):
        agent = types.SimpleNamespace(name=name,
            signing_public=ed25519.Ed25519PublicKey.from_public_bytes(unb64(pub['sign'])),
            exchange_public=unb64(pub['exchange']))
        domain.register(agent)
    for name, pub in config['agents'].items():
        register(name, pub)
    domain.configure_task('stock', list(config['agents']))
    domain.objects['inventory'] = (2, {'retail'}, Path(config['store']).read_bytes())
    for resource,path in config.get('resource_files',{}).items():
        if resource not in domain.objects:raise ValueError('unknown configured resource')
        level,compartments,_=domain.objects[resource]
        domain.objects[resource]=(level,compartments,Path(path).read_bytes())
    admin_token = config['admin_token']
    started = time.time()
    soc = None
    if config.get('soc'):
        from soc.bridge import Bridge
        soc = Bridge(domain, config['soc'])
    if config.get('assurance'):
        from assurance.integration import attach
        attach(domain,config['assurance'],soc.journal if soc else None)
    from enterprise.masking import install
    install(domain, config.get('dlp', {'enabled': True}), soc.journal if soc else None)

    class Handler(socketserver.StreamRequestHandler):
        def write(self, value):
            self.wfile.write(json.dumps(value, allow_nan=False).encode() + b'\n')
            self.wfile.flush()

        def receive(self):
            line = self.rfile.readline(MAX_FRAME + 1)
            if not line:
                return None
            if len(line) > MAX_FRAME or not line.endswith(b'\n'):
                raise Denied('oversized or incomplete frame')
            message = json.loads(line)
            if not isinstance(message, dict):
                raise Denied('RPC must be an object')
            return message

        def handle(self):
            self.bound_principal=None
            try:self.handle_session()
            finally:
                principal=self.bound_principal
                if principal and principal!='@admin':
                    with domain.lock:
                        for sid,session in list(domain.sessions.items()):
                            if session.grant['agent']==principal and session.state!='REVOKED':
                                try:domain.revoke(sid,'strict transport continuity break')
                                except Exception:pass  # Local revoke occurs even if global quorum is unavailable.

        def handle_session(self):
            self.request.settimeout(5)
            nonce = secrets.token_hex(32)
            self.write({'nonce': nonce, 'gateway_public': b64(domain.verifier.public_bytes_raw())})
            principal = None
            try:
                hello = self.receive()
                if hello is None:
                    return
                if hello.get('kind') == 'admin':
                    if not hmac.compare_digest(str(hello.get('token', '')), admin_token):
                        raise Denied('admin authentication failed')
                    principal = '@admin'
                else:
                    principal = hello.get('agent')
                    identity = domain.identities.get(principal)
                    if not identity:
                        raise Denied('unknown transport principal')
                    identity['sign'].verify(unb64(hello.get('signature', '')),
                        canon({'agent': principal, 'transport_nonce': nonce}))
                self.bound_principal=principal
                self.write({'ok': True, 'principal': principal})
                self.request.settimeout(60 if principal != '@admin' else 5)
            except Exception:
                self.write({'ok': False, 'error': 'transport authentication failed'})
                return
            while True:
                try:
                    msg = self.receive()
                    if msg is None:
                        return
                    if soc:soc.begin_request(principal,msg)
                    op = msg.get('op')
                    if op == 'admin':
                        if principal != '@admin':
                            raise Denied('admin channel required')
                        method = msg.get('method')
                        args = msg.get('args', {})
                        if not isinstance(args, dict):
                            raise Denied('invalid admin arguments')
                        if method == 'snapshot':
                            result = {'release_count': domain.release_count,
                                'challenge_count': len(domain.challenges),
                                'sessions': len(domain.sessions),
                                'session_states':{sid:s.state for sid,s in domain.sessions.items()},
                                'now': domain.clock.now(), 'pid': os.getpid(), 'mode': mode,
                                'uptime': time.time() - started}
                        elif method == 'register':
                            register(args['name'], args['public']); result = True
                        elif method == 'fixture_expiry':
                            # Test-only shortening, never lengthens the original 60s grant.
                            with domain.lock:
                                session = domain.sessions[args['sid']]
                                session.grant['expires'] = min(session.grant['expires'],
                                                              domain.clock.now() + 0.15)
                            result = True
                        elif method in ('revoke', 'update_policy', 'update_task',
                                        'change_environment', 'change_group',
                                        'set_identity_enabled', 'checkpoint'):
                            result = getattr(domain, method)(**args)
                        else:
                            raise Denied('unknown administration method')
                        if soc:soc.admin_event(method,args)
                    else:
                        if principal == '@admin':
                            raise Denied('admin channel cannot perform agent RPC')
                        if op in ('challenge', 'admit'):
                            request = msg.get('request')
                            if mode == 'hardened' and (not isinstance(request, dict)
                                    or request.get('agent') != principal):
                                raise Denied('transport principal/request mismatch')
                        if op == 'challenge':
                            result = domain.challenge(msg.get('request'))
                        elif op == 'admit':
                            result = domain.admit(msg.get('request'), msg.get('challenge'),
                                                  msg.get('proof'), msg.get('approval'))
                        elif op == 'operate':
                            signed = msg.get('signed')
                            if mode == 'hardened' and isinstance(signed, dict):
                                body = signed.get('body')
                                if isinstance(body, dict) and body.get('agent') != principal:
                                    raise Denied('transport principal/operation mismatch')
                            result = domain.operate(msg.get('signed'))
                        elif op == 'health':
                            result = {'now': domain.clock.now(), 'mode': mode}
                        else:
                            raise Denied('unknown RPC')
                    self.write({'ok': True, 'result': result})
                except (Denied, ValueError, TypeError, KeyError, AttributeError) as e:
                    if soc:
                        try:soc.denial(principal,e)
                        except Exception:pass
                    self.write({'ok': False, 'error': str(e)[:160],
                                'type': type(e).__name__})
                except (TimeoutError, ConnectionError, OSError):
                    return
                except Exception:
                    self.write({'ok': False, 'error': 'controlled internal failure'})

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        request_queue_size = 64
    with Server(('127.0.0.1', int(requested_port)), Handler) as server:
        print(json.dumps({'ready': True, 'pid': os.getpid(), 'mode': mode,
                          'address': list(server.server_address),
                          'soar_url':soc.soar.url if soc else None}), flush=True)
        try:server.serve_forever(poll_interval=0.05)
        finally:
            if soc:soc.close()


if __name__ == '__main__':
    main()
