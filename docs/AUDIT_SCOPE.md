# Third-party audit handoff - AA-ZTCE

Proposal originator: Abid Yousef. Prepared 15 October 2026.

## Scheduling status

NOT SCHEDULED. No independent auditor, engagement terms, budget, availability window or contact has been selected. This tightened edition is ready for recipient-specific handoff. No invitation, message, purchase or representation of third-party review has been made. This is a prepared scope for an external engagement, not an audit opinion.

## Objective

Independently assess the included reference implementation, test evidence and formal abstraction. Establish which claims are supported, which controls are incomplete and whether any critical bypasses exist. Distinguish prototype limitations from vulnerabilities in a production deployment. The code is a local test harness, not a deployed product.

## In-scope review

### Token and session lifecycle

- Challenge generation, request binding, single use and expiration.
- Authority approval scope, proof verification, request binding and reuse prevention.
- Session issuance, maximum lifetime, disablement, checkpoint state and revocation.
- Recovery creates fresh sessions; revoked identifiers remain rejected.
- Replay-cache scope, growth, cleanup and resource-exhaustion behavior.
- Clock assumptions and boundary conditions, including expiry equality.
- Effect of policy, environment and group-generation changes on existing grants.

### Cryptographic validation

- Ed25519 verification paths and canonical message encoding.
- Coverage of recipient, audience, session, resource, destination and action.
- X25519/HKDF session derivation, key separation and authenticated server-key binding.
- AES-GCM nonce and associated-data handling, cross-agent isolation and ciphertext tampering.
- Key custody, evidence signer trust and encrypted storage requirements not implemented here.
- Whether forward secrecy is required; the current long-term client exchange key design must not be described as a reviewed Signal/WhatsApp protocol.
- Reject unsupported, malformed and ambiguous encodings without unsafe fallback.

### Policy evaluation and boundaries

- Mandatory independent checks cannot be compensated by unrelated positive evidence.
- Clearance and compartment rules; task authority and combined-workflow dependencies.
- Denial before resource release, including alternate names, tools and destinations.
- Evidence staleness, unknown state and unavailable-verifier behavior.
- Complete mediation of backing stores and tools in a future deployment.
- Direct-memory access within the single process is outside the current isolation claim.
- Interaction between grants, operator mutations, queued work and commit-time checks.
- Threat model for false trusted evidence and policy-authority compromise.

### Formal assurance

- Review the single-session abstraction, transition relation, invariants and assumptions.
- Reproduce each SMT-LIB query in an independently installed solver.
- Challenge vacuity and omitted transitions; examine negative-control counterexamples.
- Establish a separate implementation-refinement argument before claiming verified source code.
- The 16-bit rights-set theorem describes a proposed delegation rule, not a full implemented delegation-chain protocol.

## Explicit exclusions requiring a separate environment

Live multi-model prompt-injection benchmarking; a VM/container deployment; kernel-exploit research; production remote attestation; distributed key-broker/cache failures; full organizational approval hierarchy; real user data; reliable cognitive disruption and computational distortion efficacy.

## Known gaps to verify independently

The runtime is in-process and its data structures can be accessed directly by trusted harness code. Environment and collective-assessment verdicts are simulated evidence. Malformed-input handling, network parsers, persistence, credential storage, memory cleanup and operational rate limits are not production hardened. An authorized recipient can retain plaintext; a malicious in-scope action can pass; a dishonest trusted verifier can cause admission. These must remain prominent in any report.

## Deliverables requested from the auditor

1. Reviewed source hash manifest and reproducible environment details.
2. Findings with severity, affected boundary, evidence and replayable reproduction.
3. Review of crypto/session assumptions and a written implementation-threat model.
4. Independent reproduction of tests and solver results, with additions for missed cases.
5. Remediation recommendations and a separate retest report after fixes.
6. A scoped assurance statement explicitly listing exclusions and residual risks.

## Proposed engagement sequence

Scope and terms agreement; source/evidence handoff; auditor-led review and testing; findings debrief; remediation; independent retest; final report. Dates and fees must be agreed with the selected provider. No speculative calendar appointment is created by this document.

## Evidence package

`engine.py`, `adversarial_simulations.py`, `formal_checks.py`, generated JSON results, all SMT queries, a SHA-256 manifest and the prior test packages are included. No real credentials or production records are included.

## Tightened edition: mandatory independent retest

Reproduce all five before/after findings in finding_reproductions.json. Review identity-generation and key pinning, full task snapshot binding, register/configure/update lock coverage, schema and finite-time validation, challenge quotas, session/request budgets and bounded event retention. Inspect direct mutable registry access as a trusted-control-plane assumption. Test actual distributed services separately; a process lock is not a cross-host transaction.

Reproduce the 5,000-action seeded campaign, 120 thread trials and original 61 regression cases. Inspect all 20 solver queries, including the added identity/task binding and quota properties. The SMT abstraction is not a source-level proof.

This edition supersedes the previous core engine for the audit. Historical artifacts are reference evidence only and must not be used as the fixed runtime. The external audit remains unperformed.
