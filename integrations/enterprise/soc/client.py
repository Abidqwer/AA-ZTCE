"""Small dependency-free client suitable for a SOAR Python action/playbook."""
import json
import ssl
import urllib.error
import urllib.request
from .events import canonical
from .soar import signed_headers


def request(url,key_id,secret,method,target,body=None,ca_file=None,cert_file=None,key_file=None,headers=None,audience='Domain-X'):
    data=canonical(body) if body is not None else b''
    ctx=ssl.create_default_context(cafile=ca_file)
    if cert_file:ctx.load_cert_chain(cert_file,key_file)
    signed=headers or signed_headers(secret,key_id,method,target,data,audience=audience)
    call=urllib.request.Request(url+target,data=data if method in ('POST','PUT','DELETE') else None,headers=signed,method=method)
    try:
        with urllib.request.urlopen(call,context=ctx,timeout=5) as response:
            return response.status,json.load(response)
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read())
