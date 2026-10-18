"""Bounded mutual-TLS JSON client, without redirects or insecure fallback."""
import json
import ssl
import urllib.request
import urllib.error


def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


class HTTPS:
    def __init__(self,url,ca_file,cert_file,key_file,timeout=5):
        from urllib.parse import urlsplit
        u=urlsplit(url)
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
            raise ValueError('HTTPS origin required')
        ctx=ssl.create_default_context(cafile=ca_file);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_file,key_file)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),NoRedirect())
        self.url=url.rstrip('/');self.timeout=timeout
    def post(self,path,body):
        data=canonical(body)
        if len(data)>131072:raise ValueError('request too large')
        request=urllib.request.Request(self.url+path,data=data,headers={'Content-Type':'application/json'},method='POST')
        try:
            with self.opener.open(request,timeout=self.timeout) as response:
                payload=response.read(131073)
                if len(payload)>131072:raise ValueError('response too large')
                return json.loads(payload)
        except urllib.error.HTTPError as e:
            raise ValueError('assurance service rejected request: HTTP '+str(e.code)) from None
