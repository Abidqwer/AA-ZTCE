"""SIEM HTTP/Splunk HEC/Elasticsearch bulk/syslog-TLS delivery adapters."""
import datetime
import ipaddress
import json
import os
import socket
import ssl
import threading
import urllib.parse
import urllib.request
from .events import canonical
from .ecs import to_ecs


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def tls_context(config):
    ctx=ssl.create_default_context(cafile=config.get('ca_file'))
    if config.get('client_cert'):ctx.load_cert_chain(config['client_cert'],config.get('client_key'))
    return ctx


def http_url(config):
    url=config['url'];parts=urllib.parse.urlsplit(url)
    if parts.username or parts.password or parts.fragment:raise ValueError('invalid sink URL')
    if parts.scheme!='https':
        try:loopback=ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:loopback=False
        if not (parts.scheme=='http' and loopback and config.get('allow_loopback_http')):
            raise ValueError('HTTPS required outside explicit local tests')
    return url


def send(config,event):
    kind=config['type'];token=os.environ.get(config.get('token_env',''),'')
    document=to_ecs(event)
    if config.get('token_env') and not token:raise ValueError('missing SIEM token environment variable')
    if kind=='syslog_tls':
        stamp=datetime.datetime.fromtimestamp(event['timestamp'],datetime.timezone.utc).isoformat().replace('+00:00','Z')
        severity=3 if event['severity']>=7 else 5
        payload=(f'<{16*8+severity}>1 {stamp} aa-ztce AA-ZTCE - SECURITY - '+canonical(document).decode()).encode()
        # RFC 5425 octet-counted framing over a verified TLS connection.
        with socket.create_connection((config['host'],int(config.get('port',6514))),timeout=3) as raw:
            with tls_context(config).wrap_socket(raw,server_hostname=config['host']) as channel:
                channel.sendall(str(len(payload)).encode()+b' '+payload)
        return
    headers={'Content-Type':'application/json'}
    if kind=='splunk_hec':
        if not token:raise ValueError('Splunk HEC requires a token')
        headers['Authorization']='Splunk '+token
        payload={'time':event['timestamp'],'host':event['domain_id'],'source':'AA-ZTCE',
                 'sourcetype':'aa_ztce:security','event':document}
        if config.get('index'):payload['index']=config['index']
        data=canonical(payload)
    elif kind=='elastic_bulk':
        headers['Content-Type']='application/x-ndjson'
        if token:headers['Authorization']='ApiKey '+token
        data=canonical({'create':{'_index':config.get('index','aa-ztce-security'),
                                  '_id':event['event_id']}})+b'\n'+canonical(document)+b'\n'
    elif kind=='json_webhook':
        if token:headers['Authorization']='Bearer '+token
        headers['Idempotency-Key']=event['event_id'];data=canonical(document)
    else:raise ValueError('unsupported SIEM sink')
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=tls_context(config)))
    request=urllib.request.Request(http_url(config),data=data,headers=headers,method='POST')
    with opener.open(request,timeout=3) as response:
        body=response.read(65537)
        if len(body)>65536:raise ValueError('oversized SIEM acknowledgment')
        if kind=='splunk_hec' and json.loads(body).get('code')!=0:
            raise ValueError('Splunk rejected event')
        if kind=='elastic_bulk':
            reply=json.loads(body);items=reply.get('items',[])
            if len(items)!=1 or any(next(iter(item.values())).get('status') not in (200,201,409) for item in items):
                raise ValueError('Elasticsearch rejected event')


class Exporter:
    def __init__(self,journal,sinks):
        self.journal=journal;self.sinks={s['id']:s for s in sinks}
        self.stop_event=threading.Event();self.thread=threading.Thread(target=self.run,daemon=True)
        for s in sinks:
            if s['type']!='syslog_tls':http_url(s)
    def start(self):self.thread.start()
    def flush_once(self):
        for event_id,sink,payload,_ in self.journal.due():
            if self.stop_event.is_set():break
            try:send(self.sinks[sink],json.loads(payload));self.journal.delivered(event_id,sink)
            except Exception as e:self.journal.delivered(event_id,sink,e)
    def run(self):
        while not self.stop_event.is_set():
            try:self.flush_once()
            except Exception:pass  # Keep queued rows; never acknowledge an unperformed delivery.
            self.stop_event.wait(0.1)
    def close(self):
        self.stop_event.set()
        if self.thread.is_alive():self.thread.join(timeout=15)
