#!/usr/bin/env python3
"""Security-relevant enterprise checks; all data and workloads are synthetic."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from enterprise.masking import DataMasker, MaskingError, install
from enterprise.keys import SoftwareEd25519
from enterprise.taxonomy import enrich
from runtime_engine import fixture, enroll, Denied
from soc.ecs import to_ecs
from soc.events import Journal
from soc.setup import initialize
from soc.client import request
from verify import Deployment

ROOT=Path(__file__).resolve().parent


class EnterpriseTests(unittest.TestCase):
    def test_software_signer_rejects_tamper(self):
        from cryptography.exceptions import InvalidSignature
        key=SoftwareEd25519();key.public_key().verify(key.sign(b'policy'),b'policy')
        with self.assertRaises(InvalidSignature):key.public_key().verify(key.sign(b'policy'),b'other')

    def test_pii_and_plain_business_data(self):
        value=b'SSN 123-45-6789; card 4111 1111 1111 1111; email test@example.org; total=125'
        output,counts=DataMasker().mask(value)
        self.assertEqual(counts,{'SSN':1,'EMAIL':1,'PAN':1})
        for secret in [b'123-45-6789',b'4111',b'test@example.org']:self.assertNotIn(secret,output)
        self.assertIn(b'total=125',output)

    def test_invalid_luhn_not_claimed_detected(self):
        data=b'4111 1111 1111 1112';self.assertEqual(DataMasker().mask(data),(data,{}))

    def test_encoded_data_is_explicit_known_miss(self):
        value=b'Encoded SSN MTIzLTQ1LTY3ODk=';self.assertEqual(DataMasker().mask(value),(value,{}))

    def test_bad_text_and_bounds_fail_closed(self):
        for value in [b'\xff', b'A'*9]:
            with self.assertRaises(MaskingError):DataMasker(8).mask(value)
        with self.assertRaises(ValueError):DataMasker(0)

    def test_wrong_configuration_rejected(self):
        _,domain,_=fixture()
        with self.assertRaises(ValueError):install(domain,{'backend':'silently_unknown'})
        with self.assertRaises(ValueError):install(domain,{'enabled':'false'})

    def test_dlp_preserves_ciphertext_boundary(self):
        authority,domain,agents=fixture();a=agents['A'];sid=enroll(authority,domain,a)
        domain.objects['inventory']=(2,{'retail'},b'SSN 123-45-6789 total=125')
        install(domain,{'enabled':True})
        envelope=domain.operate(a.request(sid,'inventory','internal',now=domain.clock.now()))
        self.assertEqual(a.decrypt(envelope),b'SSN [SSN_REDACTED] total=125')
        self.assertNotIn('123-45-6789',json.dumps(envelope))

    def test_unauthorized_does_not_scan(self):
        authority,domain,agents=fixture();a=agents['A'];sid=enroll(authority,domain,a)
        calls=[];domain.release_transform=lambda *args:calls.append(args)
        with self.assertRaises(Denied):domain.operate(a.request(sid,'defence','internal',now=domain.clock.now()))
        self.assertEqual(calls,[]);self.assertEqual(domain.release_count,0)

    def test_scan_failure_blocks_release(self):
        authority,domain,agents=fixture();a=agents['A'];sid=enroll(authority,domain,a)
        domain.objects['inventory']=(2,{'retail'},b'\xff');install(domain,{'enabled':True})
        with self.assertRaises(Denied):domain.operate(a.request(sid,'inventory','internal',now=domain.clock.now()))
        self.assertEqual(domain.release_count,0)

    def test_mask_audit_contains_no_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            authority,domain,agents=fixture();a=agents['A'];sid=enroll(authority,domain,a)
            journal=Journal(Path(tmp)/'events.sqlite','Domain-X')
            try:
                domain.objects['inventory']=(2,{'retail'},b'123-45-6789')
                install(domain,{'enabled':True},journal)
                domain.operate(a.request(sid,'inventory','internal',now=domain.clock.now()))
                rows=journal.read();self.assertEqual(rows[0]['redaction_count'],1)
                self.assertNotIn('123-45-6789',json.dumps(rows));self.assertTrue(journal.verify_chain()['valid'])
            finally:journal.close()

    def test_workflow_update_invalidates_previously_approved_grant(self):
        from enterprise.workflows import Workflows
        with tempfile.TemporaryDirectory() as tmp:
            authority,domain,agents=fixture();a=agents['A']
            journal=Journal(Path(tmp)/'state.sqlite','Domain-X')
            try:
                registry=Workflows(domain,journal)
                client={'id':'admin','actions':['manage_workflows'],'agents':['A'],
                    'resources':['inventory'],'destinations':['internal']}
                definition={'agents':['A'],'resources':['inventory'],'destinations':['internal'],
                    'purpose':'inventory-analysis','expected_revision':0}
                registry.handle(client,'PUT','scoped',definition)
                sid=enroll(authority,domain,a,domain.admission_request('A',task_id='scoped'))
                domain.operate(a.request(sid,now=domain.clock.now()))
                registry.handle(client,'PUT','scoped',{**definition,'purpose':'changed','expected_revision':1})
                with self.assertRaises(Denied):domain.operate(a.request(sid,now=domain.clock.now()))
                registry.handle(client,'DELETE','scoped',{'expected_revision':2})
                self.assertEqual(domain.sessions[sid].state,'REVOKED')
            finally:journal.close()

    def test_no_automatic_attribution(self):
        event=to_ecs({'event_type':'decision.denied','event_id':'example','timestamp':0,'domain_id':'Domain-X'})
        self.assertNotIn('threat',event)
        tagged=enrich(event,'AML.T0051',basis='synthetic_test',evidence_id='fixture-001')
        self.assertEqual(tagged['threat']['technique'][0]['name'],'LLM Prompt Injection')
        self.assertTrue(tagged['aa_ztce']['attribution']['simulated']);self.assertNotIn('threat',event)
        self.assertEqual(enrich(event,'AML.T0052',basis='analyst_review',evidence_id='case-1')['threat']['technique'][0]['name'],'Phishing')
        with self.assertRaises(ValueError):enrich(event,'T0052',basis='synthetic_test',evidence_id='fixture')
        with self.assertRaises(ValueError):enrich(event,'AML.T0051',basis='agent_says_so',evidence_id='fixture')

    def test_real_gateway_masks_before_worker_decrypt(self):
        deployment=Deployment('hardened',content='SYNTHETIC SSN 123-45-6789 total=125')
        try:
            session=deployment.enroll('A');self.assertTrue(session['ok'])
            result=deployment.workers['A'].call('operate',sid=session['sid'],resource='inventory',destination='internal')
            self.assertTrue(result['ok']);self.assertEqual(result['plaintext'],'SYNTHETIC SSN [SSN_REDACTED] total=125')
        finally:deployment.close()


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.config=initialize(cls.root)
        operator=cls.config['soar']['clients'][0]
        operator['actions'].append('manage_workflows');operator['resources']=['inventory'];operator['destinations']=['internal']
        cls.deployment=Deployment('hardened',soc=cls.config)
        cls.operator=operator;cls.secret=Path(operator['key_file']).read_text().strip()
    @classmethod
    def tearDownClass(cls):cls.deployment.close();cls.temp.cleanup()
    def call(self,method,name,body=None):
        cfg=self.config['soar']
        return request(self.deployment.boot['soar_url'],self.operator['id'],self.secret,method,'/v1/workflows/'+name,body,
            ca_file=cfg['cert_file'],cert_file=cfg['cert_file'],key_file=cfg['key_file'])
    def document(self,**changes):
        return dict({'agents':['A'],'resources':['inventory'],'destinations':['internal'],'purpose':'synthetic analysis','expected_revision':0},**changes)
    def test_crud_and_revision_conflict(self):
        status,result=self.call('PUT','managed_test',self.document());self.assertEqual(status,200);self.assertEqual(result['revision'],1)
        self.assertEqual(self.call('GET','managed_test')[1]['purpose'],'synthetic analysis')
        self.assertEqual(self.call('PUT','managed_test',self.document())[0],409)
        self.assertEqual(self.call('PUT','managed_test',self.document(expected_revision=1,purpose='revised'))[1]['revision'],2)
        self.assertEqual(self.call('DELETE','managed_test',{'expected_revision':2})[0],200)
        self.assertEqual(self.call('GET','managed_test')[0],404)
    def test_scope_reserved_and_bad_body(self):
        self.assertEqual(self.call('PUT','stock',self.document())[0],400)
        self.assertEqual(self.call('PUT','unauthorized',self.document(resources=['defence']))[0],403)
        self.assertEqual(self.call('PUT','bad_input',self.document(agents=['unknown']))[0],403)
        self.assertEqual(self.call('PUT','bad_shape',{'expected_revision':False})[0],400)
    def test_missing_admin_role(self):
        from enterprise.workflows import Workflows,WorkflowError
        authority,domain,_=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            journal=Journal(Path(tmp)/'w.sqlite','Domain-X')
            try:
                registry=Workflows(domain,journal)
                with self.assertRaises(WorkflowError):registry.handle({'id':'no-role','actions':[]},'GET','test')
            finally:journal.close()
    def test_restart_preserves_desired_workflow(self):
        self.assertEqual(self.call('PUT','persistent_test',self.document())[0],200)
        from enterprise.workflows import Workflows
        authority,domain,_=fixture();journal=Journal(self.root/'soc.sqlite','Domain-X')
        try:
            registry=Workflows(domain,journal)
            self.assertIn('persistent_test',domain.tasks)
            self.assertEqual(domain.tasks['persistent_test']['purpose'],'synthetic analysis')
        finally:journal.close()
    @unittest.skipUnless(os.environ.get('AA_ZTCE_GO'),'Go executable not supplied')
    def test_go_provider_real_gateway_lifecycle(self):
        cfg=self.config['soar']
        data={'endpoint':self.deployment.boot['soar_url'],'key_id':self.operator['id'],
            'key_file':self.operator['key_file'],'ca_file':cfg['cert_file'],
            'cert_file':cfg['cert_file'],'cert_key_file':cfg['key_file']}
        path=self.root/'go-provider-test.json';path.write_text(json.dumps(data))
        run=subprocess.run([os.environ['AA_ZTCE_GO'],'test','-count=1','-run','TestGatewayLifecycle','-v','./...'],
            cwd=ROOT/'terraform-provider-aaztce',env={**os.environ,'AA_ZTCE_PROVIDER_CONFIG':str(path)},
            capture_output=True,text=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(self.call('GET','go_provider_test')[0],404)
    @unittest.skipUnless(os.environ.get('AA_ZTCE_TERRAFORM'),'Terraform executable not supplied')
    def test_real_terraform_lifecycle(self):
        import socket
        try:
            probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);probe.close()
        except PermissionError:
            self.skipTest('Host forbids AF_UNIX sockets required by Terraform go-plugin on Linux')
        exe=os.environ['AA_ZTCE_TERRAFORM'];provider=ROOT/'terraform-provider-aaztce'
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);rc=folder/'terraform.rc'
            rc.write_text('provider_installation { dev_overrides { "local/abid/aaztce" = '+json.dumps(str(provider))+' } direct {} }\n')
            config={'terraform':{'required_providers':{'aaztce':{'source':'local/abid/aaztce'}}},
                'provider':{'aaztce':{'endpoint':self.deployment.boot['soar_url'],'key_id':self.operator['id'],
                    'key_file':self.operator['key_file'],'ca_file':self.config['soar']['cert_file'],
                    'cert_file':self.config['soar']['cert_file'],'cert_key_file':self.config['soar']['key_file']}},
                'resource':{'aaztce_workflow':{'finance_agent':{'name':'terraform_test','agents':['A'],'resources':['inventory'],
                    'destinations':['internal'],'purpose':'terraform synthetic'}}}}
            (folder/'main.tf.json').write_text(json.dumps(config));env={**os.environ,'TF_CLI_CONFIG_FILE':str(rc),'TF_IN_AUTOMATION':'1','CHECKPOINT_DISABLE':'1'}
            for command in [('validate','-no-color'),('apply','-auto-approve','-input=false','-no-color')]:
                run=subprocess.run([exe,*command],cwd=folder,env=env,capture_output=True,text=True,timeout=60)
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertEqual(self.call('GET','terraform_test')[0],200)
            config['resource']['aaztce_workflow']['finance_agent']['purpose']='updated by terraform'
            (folder/'main.tf.json').write_text(json.dumps(config))
            run=subprocess.run([exe,'apply','-auto-approve','-input=false','-no-color'],cwd=folder,env=env,capture_output=True,text=True,timeout=60)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertEqual(self.call('GET','terraform_test')[1]['purpose'],'updated by terraform')
            run=subprocess.run([exe,'destroy','-auto-approve','-input=false','-no-color'],cwd=folder,env=env,capture_output=True,text=True,timeout=60)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertEqual(self.call('GET','terraform_test')[0],404)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    summary={'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'limitations':['Synthetic local data; no live LLM, customer SOC, Kubernetes cluster, HSM, SVID or PQC tests.']}
    out=ROOT/'results/enterprise';out.mkdir(parents=True,exist_ok=True)
    (out/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
