"""A real separate process, confined before untrusted test commands arrive."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).parent / 'published'))
from engine import Agent, canon, b64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from confinement import confine


def main():
    name, socket_path = sys.argv[1:]
    agent = Agent(name)
    # Warm cryptographic backends before denying filesystem and process operations.
    data = b'warmup'
    agent.signing_public.verify(agent._sign.sign(data), data)
    key = AESGCM.generate_key(bit_length=256)
    cipher = AESGCM(key)
    cipher.decrypt(bytes(12), cipher.encrypt(bytes(12), data, None), None)
    print(json.dumps({'public': {'sign': b64(agent.signing_public.public_bytes_raw()),
                                 'exchange': b64(agent.exchange_public)},
                      'pid': os.getpid()}), flush=True)
    # The parent starts the gateway with our public identity, then tells us to connect.
    connect_command = json.loads(sys.stdin.readline())
    if connect_command.get('op') != 'connect':
        return
    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    channel.connect(tuple(connect_command['address']))
    wire = channel.makefile('rwb', buffering=0)
    def send(value):
        wire.write(json.dumps(value, allow_nan=False).encode() + b'\n')
    def receive():
        line = wire.readline(32769)
        if not line:
            raise ConnectionError('gateway closed')
        return json.loads(line)
    hello = receive()
    gateway_public = ed25519.Ed25519PublicKey.from_public_bytes(
        __import__('base64').b64decode(hello['gateway_public']))
    send({'agent': name, 'signature': b64(agent._sign.sign(
        canon({'agent': name, 'transport_nonce': hello['nonce']})))})
    if not receive().get('ok'):
        raise RuntimeError('transport authentication failed')
    libc = ctypes.CDLL(None, use_errno=True)
    status = confine(channel.fileno())
    print(json.dumps({'ready': True, 'isolation': status}), flush=True)
    def rpc(message):
        send(message)
        return receive()
    for line in sys.stdin:
        try:
            command = json.loads(line)
            op = command.get('op')
            if op == 'shutdown':
                break
            if op == 'rpc':
                result = rpc(command['message'])
            elif op == 'admission_request':
                result = {'agent': name, 'task': 'stock', 'resources': ['inventory'],
                          'destinations': ['internal'], 'purpose': 'inventory-analysis',
                          'audience': 'Domain-X', 'client_nonce': os.urandom(16).hex()}
            elif op == 'sign_admission':
                result = agent.sign_admission(command['request'], command['challenge'])
            elif op == 'sign_transport':
                result = b64(agent._sign.sign(canon({'agent':name,
                                                     'transport_nonce':command['nonce']})))
            elif op == 'accept':
                result = agent.accept(command['response'], gateway_public)
            elif op == 'prepare':
                result = agent.request(command['sid'], now=time.time(),
                                       **command.get('arguments', {}))
            elif op == 'operate':
                signed = agent.request(command['sid'], now=time.time(),
                                       **command.get('arguments', {}))
                result = rpc({'op': 'operate', 'signed': signed})
                if result.get('ok'):
                    result['plaintext'] = agent.decrypt(result['result']).decode()
            elif op == 'decrypt':
                result = agent.decrypt(command['envelope']).decode()
            elif op == 'probe':
                kind = command['kind']
                try:
                    if kind == 'file':
                        with open(command['path'], 'rb') as f:
                            f.read(1)
                    elif kind == 'socket':
                        socket.socket(command.get('family', socket.AF_INET), socket.SOCK_STREAM)
                    elif kind == 'spawn':
                        pid = os.fork()
                        if pid == 0:
                            os._exit(0)
                    elif kind == 'ptrace':
                        ctypes.set_errno(0)
                        ret = libc.ptrace(16, command['pid'], 0, 0)
                        if ret == -1:
                            raise OSError(ctypes.get_errno(), 'ptrace')
                    elif kind == 'process_vm_readv':
                        ctypes.set_errno(0)
                        ret = libc.process_vm_readv(command['pid'], 0, 0, 0, 0, 0)
                        if ret == -1:
                            raise OSError(ctypes.get_errno(), 'process_vm_readv')
                    elif kind == 'prctl':
                        ctypes.set_errno(0)
                        ret = libc.prctl(4, 1, 0, 0, 0)
                        if ret == -1:
                            raise OSError(ctypes.get_errno(), 'prctl')
                    elif kind == 'read_fd':
                        os.read(command['fd'], 1)
                    else:
                        raise ValueError('unknown probe')
                    result = {'blocked': False}
                except OSError as e:
                    result = {'blocked': e.errno in (errno.EPERM, errno.EACCES),
                              'errno': e.errno, 'kind': kind}
            else:
                raise ValueError('unknown command')
            print(json.dumps({'ok': True, 'result': result}, allow_nan=False), flush=True)
        except Exception as e:
            print(json.dumps({'ok': False, 'error': type(e).__name__ + ': ' + str(e)[:160]}),
                  flush=True)


if __name__ == '__main__':
    main()
