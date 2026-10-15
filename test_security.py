"""Positive, adversarial and explicit limitation tests for the local harness."""
import copy
import threading
import unittest
from cryptography.exceptions import InvalidSignature, InvalidTag
from engine import *


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.authority,self.domain,self.agents=fixture()
        self.a=self.agents['A'];self.b=self.agents['B']
    def session(self,agent=None):
        return enroll(self.authority,self.domain,agent or self.a)
    def op(self,sid,agent=None,**kw):
        return self.domain.operate((agent or self.a).request(sid,now=self.domain.clock.now(),**kw))
    def denied(self,fn,reason=None):
        before=self.domain.release_count
        with self.assertRaises(Denied) as exc:fn()
        if reason:self.assertIn(reason,str(exc.exception))
        self.assertEqual(before,self.domain.release_count,'denied operation released data')
    def attempt(self,request=None,proof_agent=None,approval=None):
        req=request or self.domain.admission_request('A')
        nonce=self.domain.challenge(req)
        return self.domain.admit(req,nonce,(proof_agent or self.a).sign_admission(req,nonce),
            approval if approval is not None else self.authority.approve(req,self.domain.clock.now()+20))
    def test_01_four_agents_complete_admission_and_decrypt(self):
        for a in self.agents.values():
            sid=self.session(a);env=self.op(sid,a)
            self.assertEqual(a.decrypt(env),self.domain.objects['inventory'][2])
        self.assertEqual(self.domain.release_count,4)
    def test_02_distinct_session_keys(self):
        sids=[self.session(a) for a in self.agents.values()]
        self.assertEqual(len({self.domain.sessions[s].key for s in sids}),4)
    def test_03_unknown_identity(self):
        self.denied(lambda:self.attempt(self.domain.admission_request('intruder')), 'unknown')
    def test_04_disabled_identity_before_admission(self):
        self.domain.identities['A']['enabled']=False
        self.denied(self.attempt,'disabled')
    def test_05_wrong_agent_signs_admission(self):
        self.denied(lambda:self.attempt(proof_agent=self.b),'instance proof')
    def test_06_admission_challenge_single_use(self):
        req=self.domain.admission_request('A');n=self.domain.challenge(req)
        proof=self.a.sign_admission(req,n);approval=self.authority.approve(req,1020)
        self.domain.admit(req,n,proof,approval)
        self.denied(lambda:self.domain.admit(req,n,proof,approval),'challenge')
    def test_07_expired_admission_challenge(self):
        req=self.domain.admission_request('A');n=self.domain.challenge(req)
        self.domain.clock.advance(11)
        self.denied(lambda:self.domain.admit(req,n,self.a.sign_admission(req,n),self.authority.approve(req,1040)),'challenge')
    def test_08_changed_admission_request(self):
        req=self.domain.admission_request('A');n=self.domain.challenge(req)
        req['destinations']=['external']
        self.denied(lambda:self.domain.admit(req,n,self.a.sign_admission(req,n),self.authority.approve(req,1020)),'challenge')
    def test_09_missing_authority_approval(self):
        req=self.domain.admission_request('A');n=self.domain.challenge(req)
        self.denied(lambda:self.domain.admit(req,n,self.a.sign_admission(req,n),None),'approval missing')
    def test_10_forged_authority(self):
        req=self.domain.admission_request('A');fake=Authority().approve(req,1020)
        self.denied(lambda:self.attempt(req,approval=fake),'signature')
    def test_11_approval_for_other_agent(self):
        approval=self.authority.approve(self.domain.admission_request('B'),1020)
        self.denied(lambda:self.attempt(approval=approval),'binding')
    def test_12_expired_approval(self):
        req=self.domain.admission_request('A')
        self.denied(lambda:self.attempt(req,approval=self.authority.approve(req,999)),'freshness')
    def test_13_approval_reuse(self):
        req=self.domain.admission_request('A');approval=self.authority.approve(req,1020)
        self.attempt(req,approval=approval)
        self.denied(lambda:self.attempt(req,approval=approval),'reuse')
    def test_14_authority_secret_not_in_grant(self):
        response=self.attempt();text=json.dumps(response)
        self.assertNotIn(b64(self.authority._key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())),text)
        self.assertNotIn('key',response['grant'])
    def test_15_isolation_failure_blocks_admission(self):
        self.domain.environments['A']['isolation']=False
        self.denied(self.attempt,'environment')
    def test_16_unknown_environment_evidence_fails_closed(self):
        self.domain.verifier_available=False
        self.denied(self.attempt,'environment')
    def test_17_stale_environment_blocks_admission(self):
        self.domain.environments['A']['expires']=999
        self.denied(self.attempt,'environment')
    def test_18_unapproved_destination_blocks_admission(self):
        req=self.domain.admission_request('A',destinations=('external',))
        self.denied(lambda:self.attempt(req),'scope')
    def test_19_collective_assessment_failure(self):
        self.domain.groups['stock']['assessment']='FAIL'
        self.denied(self.attempt,'collective')
    def test_20_collective_assessment_unknown(self):
        self.domain.groups['stock']['assessment']='UNKNOWN'
        self.denied(self.attempt,'collective')
    def test_21_scope_exceeds_authorized_task(self):
        req=self.domain.admission_request('A',resources=('inventory','defence'))
        self.denied(lambda:self.attempt(req),'scope')
    def test_22_clearance_is_independent_critical_gate(self):
        self.domain.tasks['stock']['resources'].add('defence')
        req=self.domain.admission_request('A',resources=('defence',))
        self.denied(lambda:self.attempt(req),'clearance')
    def test_23_compartment_not_implied_by_high_clearance(self):
        self.domain.identities['A']['clearance']=7
        self.domain.tasks['stock']['resources'].add('defence')
        req=self.domain.admission_request('A',resources=('defence',))
        self.denied(lambda:self.attempt(req),'compartment')
    def test_24_wrong_agent_uses_session(self):
        sid=self.session()
        self.denied(lambda:self.op(sid,self.b),'another agent')
    def test_25_forged_request_signature(self):
        sid=self.session();req=self.a.request(sid)
        req['signature']=b64(self.b._sign.sign(canon(req['body'])))
        self.denied(lambda:self.domain.operate(req),'signature')
    def test_26_request_replay(self):
        sid=self.session();req=self.a.request(sid)
        self.domain.operate(req)
        self.denied(lambda:self.domain.operate(req),'replay')
    def test_27_request_body_tamper(self):
        sid=self.session();req=self.a.request(sid);req['body']['destination']='external'
        self.denied(lambda:self.domain.operate(req),'signature')
    def test_28_wrong_audience(self):
        sid=self.session();req=self.a.request(sid);req['body']['audience']='Other-Domain'
        req['signature']=b64(self.a._sign.sign(canon(req['body'])))
        self.denied(lambda:self.domain.operate(req),'audience')
    def test_29_stale_request(self):
        sid=self.session();req=self.a.request(sid,now=990)
        self.denied(lambda:self.domain.operate(req),'freshness')
    def test_30_expired_session(self):
        sid=self.session();self.domain.clock.advance(61)
        self.denied(lambda:self.op(sid),'expired')
    def test_31_same_connection_boundary_attempt_revokes(self):
        sid=self.session()
        self.denied(lambda:self.op(sid,resource='defence'),'boundary')
        self.assertEqual(self.domain.sessions[sid].state,'REVOKED')
        self.denied(lambda:self.op(sid),'inactive')
    def test_32_changed_connection_requires_reassessment(self):
        sid=self.session();self.domain.change_environment('A',paths={'internal','external'})
        self.denied(lambda:self.op(sid),'environment changed')
    def test_33_loss_of_isolation_blocks_active_session(self):
        sid=self.session();self.domain.change_environment('A',isolation=False)
        self.denied(lambda:self.op(sid),'environment')
    def test_34_new_group_member_invalidates_old_grant(self):
        sid=self.session();self.domain.change_group('stock',{'A','B','C','D','E'})
        self.denied(lambda:self.op(sid),'group changed')
    def test_35_policy_change_invalidates_old_grant(self):
        sid=self.session();self.domain.policy_version+=1
        self.denied(lambda:self.op(sid),'policy changed')
    def test_36_pending_checkpoint_pauses_release(self):
        sid=self.session();self.domain.checkpoint(sid,'PENDING')
        self.denied(lambda:self.op(sid),'checkpoint')
        self.domain.checkpoint(sid,'PASS');self.op(sid)
    def test_37_failed_checkpoint_revokes(self):
        sid=self.session();self.domain.checkpoint(sid,'FAIL')
        self.denied(lambda:self.op(sid),'inactive')
    def test_38_checkpoint_cannot_restore_revoked_session(self):
        sid=self.session();self.domain.revoke(sid)
        self.denied(lambda:self.domain.checkpoint(sid,'PASS'),'cannot reactivate')
    def test_39_disconnect_requires_fresh_session(self):
        old=self.session();self.domain.disconnect(old)
        self.denied(lambda:self.op(old),'inactive')
        new=self.session();self.assertNotEqual(old,new);self.op(new)
        self.denied(lambda:self.op(old),'inactive')
    def test_40_cross_agent_ciphertext_cannot_decrypt(self):
        sa=self.session();sb=self.session(self.b);envelope=self.op(sa)
        modified=copy.deepcopy(envelope);modified['sid']=sb
        with self.assertRaises(InvalidTag):self.b.decrypt(modified)
    def test_41_ciphertext_tamper_detected(self):
        sid=self.session();envelope=self.op(sid)
        c=bytearray(unb64(envelope['ciphertext']));c[0]^=1;envelope['ciphertext']=b64(bytes(c))
        with self.assertRaises(InvalidTag):self.a.decrypt(envelope)
    def test_42_authenticated_metadata_tamper_detected(self):
        sid=self.session();envelope=self.op(sid);envelope['aad']['destination']='external'
        with self.assertRaises(InvalidTag):self.a.decrypt(envelope)
    def test_43_modified_grant_signature_rejected(self):
        response=self.attempt();response['grant']['resources'].append('defence')
        with self.assertRaises(InvalidSignature):self.a.accept(response,self.domain.verifier)
    def test_44_synthetic_injection_requests_external_transfer(self):
        # A scripted compromised client, not an LLM prompt-injection benchmark.
        sid=self.session()
        self.denied(lambda:self.op(sid,destination='attacker.example'),'boundary')
    def test_45_authorized_read_still_works_after_unrelated_agent_revoked(self):
        sa=self.session();sb=self.session(self.b);self.domain.revoke(sb)
        self.op(sa)
        self.denied(lambda:self.op(sb,self.b),'inactive')
    def test_46_stale_verifier_blocks_active_release(self):
        sid=self.session();self.domain.verifier_available=False
        self.denied(lambda:self.op(sid),'environment')
    def test_47_removed_task_resource_blocks_old_grant(self):
        sid=self.session();self.domain.tasks['stock']['resources'].clear()
        self.denied(lambda:self.op(sid),'boundary')
    def test_48_disabled_identity_blocks_active_release(self):
        sid=self.session();self.domain.identities['A']['enabled']=False
        self.denied(lambda:self.op(sid),'inactive')
    def test_49_serialized_revocation_with_concurrent_requests(self):
        sid=self.session();start=threading.Barrier(4);errors=[]
        def worker():
            try:
                start.wait()
                for _ in range(60):
                    try:self.op(sid)
                    except Denied:pass
            except Exception as exc:errors.append(repr(exc))
        def revoker():
            start.wait();self.domain.revoke(sid,'concurrent test')
        threads=[threading.Thread(target=worker) for _ in range(3)]+[threading.Thread(target=revoker)]
        for t in threads:t.start()
        for t in threads:t.join(5)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertFalse(errors)
        revoked=False
        for event in self.domain.events:
            if event['event']=='REVOKE':revoked=True
            if revoked:self.assertNotEqual(event['event'],'RELEASE')
        self.assertTrue(revoked)
    def test_50_thousand_requests_replay_and_positive_control(self):
        sid=self.session()
        for _ in range(1000):
            req=self.a.request(sid);env=self.domain.operate(req)
            self.assertEqual(self.a.decrypt(env),self.domain.objects['inventory'][2])
            self.denied(lambda:self.domain.operate(req),'replay')
        self.assertEqual(self.domain.release_count,1000)
    def test_51_limit_retained_plaintext_survives_revocation(self):
        sid=self.session();env=self.op(sid);plain=self.a.decrypt(env)
        self.domain.revoke(sid)
        self.assertEqual(plain,self.domain.objects['inventory'][2])
        self.assertEqual(self.a.decrypt(env),plain)
        self.denied(lambda:self.op(sid),'inactive')
    def test_52_limit_valid_identity_does_not_reveal_hidden_motive(self):
        sid=self.session()
        # Malicious intent is not in the signed request. A policy-permitted read succeeds.
        result=self.op(sid)
        self.assertEqual(self.a.decrypt(result),self.domain.objects['inventory'][2])
    def test_53_limit_false_trusted_environment_evidence_is_accepted(self):
        # Simulates a compromised verifier asserting isolation that does not exist.
        self.domain.environments['A']['isolation']=True
        sid=self.session();self.op(sid)
        self.assertEqual(self.domain.release_count,1)
    def test_54_fixed_seed_randomized_gate_matrix(self):
        import random
        rng=random.Random(20261015)
        counts={'allow':0,'deny':0}
        for _ in range(120):
            auth,d,agents=fixture();a=agents['A'];choice=rng.randrange(6)
            if choice==0:d.environments['A']['isolation']=False
            elif choice==1:d.groups['stock']['assessment']='UNKNOWN'
            elif choice==2:d.identities['A']['enabled']=False
            elif choice==3:d.verifier_available=False
            elif choice==4:d.environments['A']['expires']=999
            try:
                sid=enroll(auth,d,a);d.operate(a.request(sid))
                self.assertEqual(choice,5);counts['allow']+=1
            except Denied:
                self.assertNotEqual(choice,5);self.assertEqual(d.release_count,0);counts['deny']+=1
        self.assertGreater(counts['allow'],0);self.assertGreater(counts['deny'],0)


    def test_55_preexisting_undeclared_exit_blocks_admission(self):
        self.domain.environments['A']['paths'].add('external')
        self.denied(self.attempt,'environment')
    def test_56_repair_then_recheck_allows_new_admission(self):
        self.domain.change_environment('A',paths={'internal','external'})
        self.denied(self.attempt,'environment')
        self.domain.change_environment('A',paths={'internal'})
        sid=self.session();self.op(sid)
    def test_57_wrong_purpose_blocks_otherwise_valid_request(self):
        req=self.domain.admission_request('A');req['purpose']='employee-tracking'
        self.denied(lambda:self.attempt(req),'purpose')
    def test_58_environment_expiry_blocks_active_session(self):
        sid=self.session();self.domain.environments['A']['expires']=self.domain.clock.now()
        self.denied(lambda:self.op(sid),'environment')
    def test_59_other_compromised_agent_cannot_approve(self):
        req=self.domain.admission_request('A');approval=self.authority.approve(req,1020)
        approval['signature']=b64(self.b._sign.sign(canon(approval['body'])))
        self.denied(lambda:self.attempt(req,approval=approval),'signature')
    def test_60_unsigned_exchange_wrapper_cannot_change_signed_key(self):
        response=self.attempt();response['server_public']=b64(public(x25519.X25519PrivateKey.generate()))
        sid=self.a.accept(response,self.domain.verifier)
        self.assertEqual(self.a.decrypt(self.op(sid)),self.domain.objects['inventory'][2])

    def test_61_evidence_generation_change_requires_reassessment(self):
        sid=self.session();self.domain.change_environment('A')
        self.denied(lambda:self.op(sid),'environment changed')

if __name__=='__main__':unittest.main(verbosity=2)
