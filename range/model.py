"""Real OpenAI-compatible model transport and loopback-only llama.cpp process."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
from urllib.parse import urlsplit

TOOL_SCHEMA={'type':'object','additionalProperties':False,'required':['action','resource','destination','agent'],
    'properties':{'action':{'type':'string','enum':['read','delete','noop']},'resource':{'type':'string','maxLength':128},
        'destination':{'type':'string','maxLength':64},'agent':{'type':'string','maxLength':64}}}


class Model:
    def __init__(self,base,model,api_key=None,timeout=60):
        u=urlsplit(base)
        if u.scheme!='https' and not (u.scheme=='http' and u.hostname in ('127.0.0.1','localhost','::1')):
            raise ValueError('HTTPS or explicit loopback HTTP model endpoint required')
        if u.username or u.password or u.query or u.fragment:raise ValueError('invalid model endpoint')
        self.base=base.rstrip('/');self.model=model;self.api_key=api_key;self.timeout=timeout;self.calls=0;self.tokens=0
    def complete(self,messages,schema=TOOL_SCHEMA,max_tokens=180,seed=20261019):
        body={'model':self.model,'messages':messages,'temperature':0,'seed':seed,'max_tokens':max_tokens,
            'response_format':{'type':'json_schema','json_schema':{'name':'range_output','strict':True,'schema':schema}}}
        headers={'Content-Type':'application/json'}
        if self.api_key:headers['Authorization']='Bearer '+self.api_key
        request=urllib.request.Request(self.base+'/chat/completions',data=json.dumps(body).encode(),headers=headers)
        start=time.perf_counter()
        with urllib.request.urlopen(request,timeout=self.timeout) as response:
            raw=response.read(1048577)
            if len(raw)>1048576:raise ValueError('model response too large')
            result=json.loads(raw)
        self.calls+=1;self.tokens+=result.get('usage',{}).get('total_tokens',0)
        content=result['choices'][0]['message']['content']
        return {'parsed':json.loads(content),'raw':content,'latency_ms':(time.perf_counter()-start)*1000,
            'usage':result.get('usage',{}),'finish_reason':result['choices'][0].get('finish_reason')}


class LlamaServer:
    def __init__(self,executable,model_file,port,log_file,threads=6):
        self.log=open(log_file,'w');self.executable=executable;self.model_file=model_file
        self.process=subprocess.Popen([executable,'--model',model_file,'--host','127.0.0.1','--port',str(port),
            '--threads',str(threads),'--ctx-size','4096','--parallel','1','--no-webui'],stdout=self.log,stderr=self.log)
        self.base='http://127.0.0.1:'+str(port)+'/v1'
        deadline=time.monotonic()+90
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/health',timeout=1) as response:
                    if response.status==200:break
            except Exception:
                if self.process.poll() is not None:raise RuntimeError('llama-server exited; inspect model-server.log')
                if time.monotonic()>deadline:raise TimeoutError('local model startup')
                time.sleep(.1)
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.log.close()
    def provenance(self):
        def digest(path):
            h=hashlib.sha256()
            with open(path,'rb') as f:
                while block:=f.read(1048576):h.update(block)
            return h.hexdigest()
        return {'server_sha256':digest(self.executable),'weights_sha256':digest(self.model_file),
            'weights_file':Path(self.model_file).name,'execution':'local CPU; real model weights, not a mocked response'}
