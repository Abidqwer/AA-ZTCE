#!/usr/bin/env python3
"""Real PKCS#11/TPM protocols, mTLS witness and three-process Raft fault tests.

All TPM/HSM devices here are explicitly SOFTWARE EMULATIONS. No physical-device,
Byzantine-tolerance, military-readiness or multi-cloud assurance is implied.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
from enterprise.keys import PKCS11Ed25519,generate_pkcs11_key
from assurance.etcd import Etcd,Revocations,ConsensusUnavailable,AuthorityRevoked
from assurance.integration import attach
from assurance.testing import pki,Cluster,port
from assurance.tpm import TPM,provision,verify_quote,unb64
from assurance.transport import HTTPS,canonical
from assurance.witness import Witness,WitnessClient,b64
from runtime_engine import Authority,Domain,Agent,enroll,Denied
from soc.events import Journal,EngineEvents
from soc.setup import initialize
from soc.client import request
from verify import Deployment

ROOT=Path(__file__).resolve().parent


class AssuranceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='aa-assurance-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.certificates=pki(cls.root/'pki')
        cls.tools=os.environ.get('AA_TPM_TOOLS_DIR','');cls.module=os.environ['AA_PKCS11_MODULE']
        cls.softhsm=os.environ.get('AA_SOFTHSM_UTIL','softhsm2-util')
        tokenroot=cls.root/'tokens';tokenroot.mkdir()
        conf=cls.root/'softhsm2.conf';conf.write_text('directories.tokendir = '+str(tokenroot)+'\nobjectstore.backend = file\nlog.level = ERROR\n')
        cls.original_softhsm=os.environ.get('SOFTHSM2_CONF');os.environ['SOFTHSM2_CONF']=str(conf)
        def restore_environment():
            if cls.original_softhsm is None:os.environ.pop('SOFTHSM2_CONF',None)
            else:os.environ['SOFTHSM2_CONF']=cls.original_softhsm
        cls.addClassCleanup(restore_environment)
        cls.pin=cls.root/'pin';cls.pin.write_text(secrets.token_hex(12));cls.pin.chmod(0o600)
        run=subprocess.run([cls.softhsm,'--module',cls.module,'--init-token','--free','--label','aa-assurance',
            '--so-pin',secrets.token_hex(12),'--pin',cls.pin.read_text()],capture_output=True,timeout=10)
        if run.returncode:raise RuntimeError('SoftHSM token initialization failed')
        generate_pkcs11_key(cls.module,'aa-assurance','gateway',str(cls.pin))
        cls.hsm=PKCS11Ed25519(cls.module,'aa-assurance','gateway',str(cls.pin),allow_software_token=True)
        cls.cluster=Cluster(cls.root/'cluster',cls.certificates,os.environ['AA_ETCD']);cls.addClassCleanup(cls.cluster.close)
        cls.tpm_configs=[];cls.tpms=[];cls.journals=[];cls.soc_configs=[];nodes={}
        public_hash=hashlib.sha256(cls.hsm.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        for i in range(2):
            r=cls.root/('tpm'+str(i));r.mkdir();(r/'state').mkdir();auth=r/'auth';auth.write_text(secrets.token_hex(16));auth.chmod(0o600)
            while True:
                p=port()
                if p<65535:
                    check=socket.socket()
                    try:check.bind(('127.0.0.1',p+1));break
                    except OSError:continue
                    finally:check.close()
            process=subprocess.Popen([os.environ.get('AA_SWTPM','swtpm'),'socket','--tpm2','--tpmstate','dir='+str(r/'state'),
                '--server','type=tcp,port='+str(p)+',bindaddr=127.0.0.1','--ctrl','type=tcp,port='+str(p+1)+',bindaddr=127.0.0.1',
                '--flags','not-need-init,startup-clear'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            def close_process(p=process):
                if p.poll() is None:p.terminate();p.wait(timeout=5)
            cls.addClassCleanup(close_process);time.sleep(.1)
            cfg=provision('swtpm:host=127.0.0.1,port='+str(p),r/'keys',auth,tools_dir=cls.tools,isolated_emulator=True)
            tpm=TPM(**cfg);cls.tpms.append(tpm);cls.tpm_configs.append(cfg)
            quote=tpm.quote('ab'*32);fingerprint=hashlib.sha256(unb64(quote['pcrs'])).hexdigest()
            soc=initialize(cls.root/('soc'+str(i)));cls.soc_configs.append(soc)
            journal=Journal(Path(soc['state_dir'])/'soc.sqlite','Domain-X');cls.journals.append(journal);cls.addClassCleanup(journal.close)
            nodes['Domain-X/node'+str(i)]={'audit_public_file':cfg['public_file'],'algorithm':tpm.algorithm,'audit_key_id':tpm.key_id,
                'attestation_public_file':str(r/'keys/attestation.pem'),'approved_pcr_sha256':fingerprint,
                'client_fingerprints':[cls.certificates['node'+str(i)]['fingerprint']],'gateway_public_sha256':public_hash}
        cert=cls.certificates
        cfg={'database':str(cls.root/'witness.sqlite'),'receipt_key_file':cert['receipt_key'],
            'cert_file':cert['service']['cert'],'key_file':cert['service']['key'],'client_ca':cert['ca'],
            'nodes':nodes,'tools_dir':cls.tools}
        cls.witness=Witness(cfg);cls.witness.start();cls.addClassCleanup(cls.witness.close)
    def profile(self,i):
        c=self.certificates;node=c['node'+str(i)]
        return {'domain_id':'Domain-X','node_id':'node'+str(i),'tpm':self.tpm_configs[i],
            'witness':{'url':self.witness.url,'ca_file':c['ca'],'cert_file':node['cert'],'key_file':node['key'],
                'receipt_public_file':c['receipt_public']},'consensus':self.cluster.config_for(i),
            'consensus_control':self.cluster.config,'attest_every_operation':True}
    def fixture(self,i=0):
        authority=Authority();d=Domain(authority,key_provider=self.hsm);agents={n:Agent(n) for n in 'ABCD'}
        for a in agents.values():d.register(a)
        d.configure_task('stock',agents);d.events=EngineEvents(d,self.journals[i])
        attached=attach(d,self.profile(i),self.journals[i]);return authority,d,agents,attached
    def reader(self,i=0):return Revocations(Etcd(**self.cluster.config_for(i)),'Domain-X','node'+str(i),self.cluster.controller)
    def wc(self,i=0):
        c=self.certificates;node=c['node'+str(i)]
        return WitnessClient(HTTPS(self.witness.url,c['ca'],node['cert'],node['key']),'Domain-X','node'+str(i),c['receipt_public'])
    def test_01_hsm_signs_and_refuses_private_export(self):
        message=b'synthetic bound grant';self.hsm.public_key().verify(self.hsm.sign(message),message)
        with self.assertRaises(InvalidSignature):self.hsm.public_key().verify(self.hsm.sign(message),b'tampered')
        p=self.hsm.p11
        with self.hsm.lock,self.hsm.token.open(user_pin=self.pin.read_text()) as session:
            key=session.get_key(object_class=p.ObjectClass.PRIVATE_KEY,label='gateway')
            self.assertFalse(key[p.Attribute.EXTRACTABLE]);self.assertTrue(key[p.Attribute.SENSITIVE])
            with self.assertRaises(p.exceptions.AttributeSensitive):_ = key[p.Attribute.VALUE]
    def test_02_software_token_cannot_claim_hardware(self):
        with self.assertRaises(ValueError):PKCS11Ed25519(self.module,'aa-assurance','gateway',str(self.pin))
    def test_03_wrong_hsm_pin_no_fallback(self):
        wrong=self.root/'wrongpin';wrong.write_text(secrets.token_hex(12))
        with self.assertRaises(Exception):PKCS11Ed25519(self.module,'aa-assurance','gateway',str(wrong),allow_software_token=True)
    def test_04_tpm_signature_and_wrong_password(self):
        t=self.tpms[0];sig=t.sign(b'audit anchor');t.public_key().verify(sig,b'audit anchor',ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):t.public_key().verify(sig,b'changed',ec.ECDSA(hashes.SHA256()))
        original=t.auth_file;wrong=self.root/'wrongauth';wrong.write_text(secrets.token_hex(16));t.auth_file=str(wrong)
        try:
            with self.assertRaises(Exception):t.sign(b'must not sign')
        finally:t.auth_file=original
    def test_05_quote_nonce_and_public_key_binding(self):
        e=self.tpms[0].quote('ab'*32);record=self.witness.config['nodes']['Domain-X/node0']
        args=[(self.root/'tpm0/keys/attestation.pem').read_bytes(),record['approved_pcr_sha256']]
        self.assertTrue(verify_quote(e,'ab'*32,*args,tools_dir=self.tools))
        with self.assertRaises(ValueError):verify_quote(e,'cd'*32,*args,tools_dir=self.tools)
        with self.assertRaises(ValueError):verify_quote(e,'ab'*32,(self.root/'tpm1/keys/attestation.pem').read_bytes(),args[1],tools_dir=self.tools)
    def test_06_remote_attestation_replay_and_context(self):
        c=self.wc();context={'gateway_public_sha256':self.witness.config['nodes']['Domain-X/node0']['gateway_public_sha256'],'request_sha256':secrets.token_hex(32)}
        challenge=c.post('/v1/attestation/challenge',{'context':context});e=self.tpms[0].quote(challenge['qualifying_hex'])
        result=c.post('/v1/attestation/verify',{'nonce':challenge['nonce'],'evidence':e})
        self.assertEqual(c.checked(result)['status'],'accepted')
        with self.assertRaises(ValueError):c.post('/v1/attestation/verify',{'nonce':challenge['nonce'],'evidence':e})
        with self.assertRaises(ValueError):c.post('/v1/attestation/challenge',{'context':{**context,'gateway_public_sha256':'0'*64}})
    def test_07_mutual_tls_node_scope_and_receipt_forgery(self):
        c=self.wc()
        with self.assertRaises(ValueError):c.transport.post('/v1/head',{'domain':'Domain-X','node':'node1'})
        with self.assertRaises(Exception):c.checked({'body':{'domain':'Domain-X','node':'node0'},'signature':b64(bytes(64))})
    def test_08_signed_journal_and_external_receipt(self):
        a,d,agents,attached=self.fixture();sid=enroll(a,d,agents['A'])
        envelope=d.operate(agents['A'].request(sid,now=d.clock.now()))
        self.assertIn(b'inventory',agents['A'].decrypt(envelope))
        head=attached['witness'].head();self.assertEqual(head['sequence'],self.journals[0].read(0,500)[-1]['sequence'])
        self.assertTrue(self.journals[0].verify_chain()['valid'])
    def test_09_rollback_and_valid_local_fork_detected(self):
        journal=self.journals[0];c=self.wc();c.anchor(journal,self.tpms[0])
        import sqlite3
        backup=self.root/'rollback.sqlite'
        db=sqlite3.connect(backup)
        with journal.lock:journal.db.backup(db)
        db.close();journal.append('test.anchor.advanced');c.anchor(journal,self.tpms[0])
        old=Journal(backup,'Domain-X')
        try:
            with self.assertRaises(ValueError):c.anchor(old,self.tpms[0])
        finally:old.close()
        fork=self.root/'fork.sqlite';db=sqlite3.connect(fork)
        with journal.lock:journal.db.backup(db)
        row=db.execute('SELECT seq,payload,previous_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        payload=json.loads(row[1]);payload['domain_id']='forged';encoded=canonical(payload).decode()
        with db:db.execute('UPDATE events SET payload=?,event_hash=? WHERE seq=?',(encoded,hashlib.sha256(row[2].encode()+encoded.encode()).hexdigest(),row[0]))
        db.close();forged=Journal(fork,'Domain-X')
        try:
            self.assertTrue(forged.verify_chain()['valid'])
            with self.assertRaises(ValueError):c.anchor(forged,self.tpms[0])
        finally:forged.close()
    def test_10_witness_unavailable_blocks_release(self):
        a,d,agents,attached=self.fixture();sid=enroll(a,d,agents['A']);previous=self.journals[0].anchor_callback
        def unavailable(journal):raise ConnectionError('injected witness outage')
        self.journals[0].anchor_callback=unavailable
        try:
            with self.assertRaises(ConnectionError):d.operate(agents['A'].request(sid,now=d.clock.now()))
        finally:self.journals[0].anchor_callback=previous
        attached['witness'].anchor(self.journals[0],self.tpms[0])
    def test_11_cross_node_session_revocation(self):
        a,d,agents,_=self.fixture(0);sid=enroll(a,d,agents['A'])
        d.operate(agents['A'].request(sid,now=d.clock.now()))
        self.reader(1).change_session(sid,'A','REVOKED')
        with self.assertRaises(AuthorityRevoked):d.operate(agents['A'].request(sid,now=d.clock.now()))
    def test_12_cross_node_disable_and_fresh_admission(self):
        a,d,agents,_=self.fixture(0);sid=enroll(a,d,agents['A']);other=self.reader(1)
        other.change_agent('A',False)
        try:
            with self.assertRaises(AuthorityRevoked):d.operate(agents['A'].request(sid,now=d.clock.now()))
            with self.assertRaises(AuthorityRevoked):enroll(a,d,agents['A'])
        finally:other.change_agent('A',True)
        with self.assertRaises(AuthorityRevoked):d.operate(agents['A'].request(sid,now=d.clock.now()))
        fresh=enroll(a,d,agents['A']);d.operate(agents['A'].request(fresh,now=d.clock.now()))
    def test_13_suspend_resume_and_no_revoked_resurrection(self):
        a,d,agents,_=self.fixture();sid=enroll(a,d,agents['A']);d.checkpoint(sid,'PENDING')
        with self.assertRaises(Denied):d.operate(agents['A'].request(sid,now=d.clock.now()))
        d.checkpoint(sid,'PASS');d.operate(agents['A'].request(sid,now=d.clock.now()))
        d.revoke(sid)
        with self.assertRaises(AuthorityRevoked):self.reader(1).change_session(sid,'A','ACTIVE')
    def test_14_revocation_race_rejected_at_authorization_transaction(self):
        reader=self.reader();grant={'agent':'A','sid':secrets.token_hex(16),**reader.admission({'agent':'A'})};original=reader.client.txn
        def racing(compare,success,failure=()):
            self.reader(1).change_session(grant['sid'],'A','REVOKED');return original(compare,success,failure)
        reader.client.txn=racing
        with self.assertRaises(AuthorityRevoked):reader.authorize({'request_id':secrets.token_hex(16)},grant)
    def test_15_reader_cannot_write_revocation_or_other_node_decision(self):
        reader=self.reader()
        with self.assertRaises(ConsensusUnavailable):reader.client.txn([],[reader.put('agent','A',{'epoch':0,'disabled':False})])
        with self.assertRaises(ConsensusUnavailable):reader.client.txn([],[reader.put('last_authorized','node1',{'request':'forged'})])
    def test_16_fresh_auth_command_idempotency(self):
        reader=self.reader();command='test:'+secrets.token_hex(16)
        first=reader.change_agent('A',command_id=command);second=self.reader(1).change_agent('A',command_id=command)
        self.assertEqual(first,second)
    def test_17_real_gateway_hsm_tpm_witness_and_soar(self):
        signing={'type':'pkcs11_ed25519','module':self.module,'token_label':'aa-assurance','key_label':'gateway',
            'pin_file':str(self.pin),'allow_software_token':True}
        d0=Deployment('hardened',soc=self.soc_configs[0],signing=signing,assurance=self.profile(0))
        d1=None
        try:
            d1=Deployment('hardened',soc=self.soc_configs[1],signing=signing,assurance=self.profile(1))
            s0=d0.enroll('A');s1=d1.enroll('A');self.assertTrue(s0['ok']);self.assertTrue(s1['ok'])
            self.assertTrue(d0.workers['A'].call('operate',sid=s0['sid'])['ok'])
            self.assertTrue(d1.workers['A'].call('operate',sid=s1['sid'])['ok'])
            config=self.soc_configs[1]['soar'];operator=config['clients'][0]
            status,result=request(d1.boot['soar_url'],operator['id'],Path(operator['key_file']).read_text().strip(),
                'POST','/v1/actions',{'action':'require_reauth','agent_id':'A','command_id':secrets.token_hex(16),'case_id':'synthetic'},
                ca_file=config['cert_file'],cert_file=config['cert_file'],key_file=config['key_file'])
            self.assertEqual(status,200);self.assertEqual(result['distributed']['status'],'committed')
            self.assertFalse(d0.workers['A'].call('operate',sid=s0['sid'])['ok'])
            self.assertFalse(d1.workers['A'].call('operate',sid=s1['sid'])['ok'])
        finally:
            if d1:d1.close()
            d0.close()
    def test_17b_transport_loss_revokes_local_and_distributed_session(self):
        signing={'type':'pkcs11_ed25519','module':self.module,'token_label':'aa-assurance','key_label':'gateway',
            'pin_file':str(self.pin),'allow_software_token':True}
        deployment=Deployment('hardened',soc=self.soc_configs[1],signing=signing,assurance=self.profile(1))
        try:
            sid=deployment.enroll('A')['sid'];deployment.workers['A'].close()
            deadline=time.monotonic()+3
            while deployment.admin('snapshot')['session_states'][sid]!='REVOKED':
                if time.monotonic()>deadline:self.fail('session survived transport loss')
                time.sleep(.02)
            # Transport closure has no response acknowledging consensus commit.
            # The local session closes first; require the remote commit within
            # the same bounded deadline rather than racing the journal anchor.
            while True:
                state,_=self.reader(0).read('session',sid)
                if state and state['state']=='REVOKED':break
                if time.monotonic()>deadline:self.fail('transport revocation did not reach consensus')
                time.sleep(.02)
        finally:deployment.close()
    def test_18_leader_failure_durable_revocation(self):
        reader=self.reader();sid=secrets.token_hex(16);reader.change_session(sid,'A','REVOKED')
        leader=self.cluster.leader();self.cluster.stop(leader)
        try:
            deadline=time.monotonic()+8
            while True:
                try:
                    state,_=reader.read('session',sid);self.assertEqual(state['state'],'REVOKED');break
                except ConsensusUnavailable:
                    if time.monotonic()>deadline:raise
                    time.sleep(.1)
        finally:self.cluster.start(leader)
    def test_19_pcr_change_rejected_by_remote_verifier(self):
        c=self.wc();t=self.tpms[0]
        t.run('tpm2_pcrextend','7:sha256='+'ab'*32)
        context={'gateway_public_sha256':self.witness.config['nodes']['Domain-X/node0']['gateway_public_sha256']}
        with self.assertRaises(ValueError):c.attest(t,context)
    def test_20_quorum_loss_denies_authorization_and_admission(self):
        reader=self.reader();grant={'agent':'A','sid':secrets.token_hex(16),**reader.admission({'agent':'A'})}
        self.cluster.stop(0);self.cluster.stop(1)
        try:
            with self.assertRaises(ConsensusUnavailable):reader.authorize({'request_id':secrets.token_hex(16)},grant)
            with self.assertRaises(ConsensusUnavailable):reader.admission({'agent':'A'})
        finally:self.cluster.start(0);self.cluster.start(1)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(AssuranceTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    output=ROOT/'results/assurance';output.mkdir(parents=True,exist_ok=True)
    summary={'tests_run':result.testsRun,'passed':result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'devices':'Two software TPMs and one SoftHSM token; no physical hardware tested',
        'consensus':'Three actual local etcd processes, verified mutual TLS and enabled RBAC',
        'semantics':'Linearized authorization decisions; previously authorized in-flight work may finish',
        'not_claimed':['Physical hardware security','Byzantine fault tolerance','Instant revocation propagation','Independent defense qualification']}
    (output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
