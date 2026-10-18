# Enterprise alignment: implementation boundaries and acceptance gates

AA-ZTCE is a proposed reference architecture and research prototype. Adoption as
an enterprise architectural standard would require independent review and real
operational evidence. Nothing in this roadmap is a deployed certification.

## Identity: SPIFFE/SPIRE and RFC 8693 (planned)

1. Consume the SPIFFE Workload API through a maintained library; validate X.509
   SVID trust bundles, certificate chain, lifetime and SPIFFE URI identity. Validate
   JWT-SVID audience when that profile is selected. Reject unknown trust domains,
   malformed identities and stale bundles; test federation explicitly.
2. Map the authenticated SPIFFE ID to an existing AA-ZTCE principal through an
   administrator-controlled registry. Identity alone must not grant task authority.
3. Use a trusted OAuth authorization server implementing RFC 8693 for delegation.
   Validate subject and actor tokens; record both identities; restrict resource,
   audience, action, task and lifetime. Deny scope amplification, unapproved actors,
   cross-domain delegation and excessive delegation depth. Request-bound approvals
   and recipient-side authorization remain necessary.
4. Test SVID rotation without dropping expected workloads, compromised-key removal,
   actor substitution, confused-deputy attempts, unavailable issuers, clock faults,
   concurrent revocation and delegation chains.

Not implemented: a SPIRE server/client, SVID verifier, token-exchange endpoint or
OAuth issuer. RFC 8693 does not mathematically solve the confused-deputy problem.

Source: https://spiffe.io/docs/latest/spiffe-about/overview/
Source: https://www.rfc-editor.org/rfc/rfc8693.html

## Data protection (implemented bounded prototype)

`enterprise/masking.py` masks formatted SSNs, email addresses and Luhn-valid payment
card numbers in bounded UTF-8 content. The runtime hook runs after authorization
and before session encryption. Unknown configuration, malformed text, oversize
content and scanner errors block release; original archived source remains intact.
Only counts and resource/session references enter masking events. The default
integration gateway enables masking; explicit `dlp.enabled=false` disables it.

This scanner does not detect every sensitive datum: names, medical facts, secrets,
encoded content, natural-language identifiers and inferred information can pass.
Even successful redaction can leave valuable business information. It does not
make every permitted malicious read harmless or close the hidden-intent gap.
The old 400-workflow measurement remains unchanged. Partial display such as a last
four digits must be a data-owner decision; this prototype fully masks detections.

Next: evaluate Presidio or another maintained local scanner against domain-specific
held-out datasets. Measure entity precision/recall, downstream task utility, p95
latency and oversize/error behavior; define binary/PDF/OCR handling and egress
protection. Do not route production plaintext to a public scanner endpoint.

## Threat attribution (implemented explicit enrichment helper)

`enterprise/taxonomy.py` adds ECS threat fields only on an explicit call from an
analyst, trusted detector or labeled simulation. The ordinary gateway projection
does not infer an attack technique from a denial. Scope violations and legitimate
replans are access outcomes, not proof of injection. Publish enriched records
alongside their evidence reference; keep the original journal event unchanged.

Pinned source metadata: `enterprise/atlas_catalog.json`, MITRE ATLAS collection
2026.09. `AML.T0051` = LLM Prompt Injection; `AML.T0052` = Phishing;
`AML.T0053` = AI Agent Tool Invocation; `AML.T0086` = Exfiltration via AI Agent
Tool Invocation. Tool invocation itself is not proof of malicious intent. Do not
use invented ID `T0052 - Unauthorized Tool Execution`.

Source: https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS-latest.yaml

## Security as code (sandbox tooling)

The Go Terraform provider manages desired workflow definitions through a scoped,
revision-checked REST API. Workflow changes invalidate bound authority; they do
not issue sessions or enroll identities. A separate trusted authority must approve
admission. Backend state and TLS/operator-key files require normal protection.

The Helm chart runs a single-replica synthetic SOC sandbox with persistent audit
state. It is not distributed production agent infrastructure. Kernel/seccomp
support, image registry access, managed certificate Secrets, cluster scheduling,
storage and actual SIEM ingestion must be validated in a partner pilot.

## Cryptographic agility (partial software seam; PQC planned)

`enterprise/keys.py` defines a signing-provider interface and a tested software
Ed25519 provider. It is used by the runtime gateway. There are no HSM, TPM, KMS or
PQC implementations, and no protocol-level algorithm negotiation. A protected key
can still be abused by a compromised authorized host invoking its signer.

Next gates:

- Add capability discovery and key identifiers, algorithm allowlists, failure
  semantics and hardware-backed providers; test custody, signer authorization,
  recovery and rotation. Do not call a software boundary a hardware enclave.
- Version signature envelopes and verification registries. Bind algorithm and key
  identifiers into authenticated messages; reject downgrade and algorithm confusion.
- Evaluate **ML-DSA (FIPS 204)** for signatures. Budget signature/key size, verifier
  resource limits, multi-signer transition and audit retention. Its standardized
  form derives from Dilithium; arbitrary prestandard implementations are not equal.
- Evaluate **ML-KEM (FIPS 203)** separately for key establishment. It does not replace
  signatures; changing Ed25519 leaves X25519/session and TLS migration work.
- Select reviewed libraries and approved protocol profiles; perform interop, load,
  adverse-input, failure, rotation and recovery tests. Algorithm use alone does
  not establish FIPS module validation or defense-contractor suitability.

Sources: https://csrc.nist.gov/pubs/fips/204/final
https://csrc.nist.gov/pubs/fips/203/final

## Priority assurance gate A: hardware root of trust and attestation (planned)

**Objective:** protect signing-key custody and strengthen evidence about platform
state and previously recorded audit history. These capabilities are not presently
implemented or tested. They do not establish a 'combat-ready' or 'defense-grade'
status by themselves.

### Design requirements

1. Generate non-exportable signing keys inside an appropriate TPM 2.0 or HSM through
   the KeyProvider interface. Discover the device's actual algorithms and curves;
   do not assume every TPM supports Ed25519. If the required algorithm is unavailable,
   select an appropriately validated supporting HSM or explicitly version the
   protocol for a supported algorithm. Never silently fall back to software keys.
   Treat gateway signing, audit anchoring, attestation and TLS keys as separate roles.
2. Authenticate and authorize every signing request. Bind signed data to its purpose,
   domain, key ID, algorithm, schema version, request/session context and freshness.
   A compromised host may still invoke an accessible hardware signer or provide
   false event data. Key non-extractability does not make those operations truthful
   or authorized. Protect the collection/enforcement path and specify which host
   components remain trusted; boot measurements alone do not prove runtime integrity.
3. Add a remote-attestation verifier with explicit appraisal policy: fresh challenge
   nonces, an enrolled attestation identity, verified signatures, approved platform
   measurements/reference values and relevant measured-boot event-log validation.
   Bind the attested workload/channel to the requesting principal. Deny admission
   when required evidence is stale, replayed, unavailable or rejected. Document
   measurement coverage, update approval and post-attestation compromise limits.
4. Sign canonical journal batch heads with a separate protected audit key. Bind the
   domain, monotonic sequence, predecessor/head digest, batch coverage and key epoch.
   Keep bulk journals outside TPM NVRAM; evaluate protected counters/anchors within
   the device's endurance and capacity limits. Store accepted anchors and receipts
   in an independently administered external witness and retention system.
5. Define maximum unanchored exposure, storage exhaustion behavior, witness failure
   handling, anti-rollback, fork detection, key rollover and compromise recovery.
   A host-local TPM anchor can be a useful reference but does not replace external
   witnessing or establish that every relevant action was recorded.

### Acceptance evidence before claiming support

| Test | Required evidence |
|---|---|
| Key custody and misuse | Demonstrate non-exportability, denied unauthorized signer calls, and the documented residual power of an authorized compromised caller. |
| Attestation | Reject replayed quotes, wrong platform identity, disallowed measurements, stale evidence and invalid channel/principal bindings. |
| Audit attacks | Detect modification, truncation, rollback and conflicting histories relative to independently retained accepted anchors. Explicitly test false event submission limits. |
| Operations | Test legitimate platform updates, signer/witness outage, recovery, rotation, latency and retention with actual selected hardware. |

Sources: https://www.rfc-editor.org/rfc/rfc9334.html
https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_getcap.1/

## Priority assurance gate B: consensus-backed distributed revocation (planned)

**Objective:** define a single authoritative order of revocation and authorization
changes, and prevent disconnected or stale enforcement points from silently
continuing privileged work. No distributed revocation backend currently exists.
Consensus does not provide instantaneous communication to every node.

### Design requirements

1. Adopt an established replicated service, initially a managed/operated etcd Raft
   cluster for a crash-fault model, with authenticated membership, mutual TLS,
   least-privilege writers, protected backups and independently reviewed recovery.
   Do not implement a new consensus algorithm inside AA-ZTCE.
2. Store domain-scoped identity/session revocations, policy versions and monotonic
   authority epochs. Define the revocation's linearization point as its durable
   authoritative commit. Report separate states for a request received, quorum
   commitment and observed enforcement. The present single-host SOAR acknowledgment
   remains local; it must not be relabeled as a distributed acknowledgment.
3. Use authoritative, linearizable authorization decisions for the strict profile.
   Notification/watch streams accelerate local updates but are not proof of current
   authority. Specify ordering between an authorization decision and the protected
   side effect, and enforce resource-side fencing or transactional coordination
   wherever necessary. A read followed by an unrelated external action leaves a
   race; consensus storage alone does not remove it.
4. A disconnected or minority enforcement point must deny new protected operations
   when it cannot establish the required authority freshness. Define behavior for
   quorum loss, timeouts, partition recovery, restart, snapshot restore and clock
   uncertainty. Expired or unverifiable authority must not become permission.
5. Where an approved lower-risk profile permits cached authorization leases, state
   and measure its maximum stale-authority exposure, including lease duration,
   clock uncertainty and enforcement/in-flight effects. It cannot claim zero stale
   authority. Revocation cannot retract data already released or undo completed
   external side effects.
6. If malicious consensus participants are in scope, choose and independently
   evaluate a mature Byzantine-fault-tolerant protocol under explicit participant,
   quorum, authentication and network assumptions. Raft handles crash faults, not
   arbitrary malicious replicas. A permissioned blockchain label does not establish
   Byzantine resilience; inspect its actual ordering protocol and failure model.

### Acceptance evidence before claiming support

| Test | Required evidence |
|---|---|
| Normal operation | Measure request-to-commit and commit-to-enforcement latency separately, including p95/p99 and the declared end-to-end authorization semantics. |
| Partitions and failover | Test dropped, delayed, duplicated and reordered messages, minority isolation, leader loss and quorum loss. Confirm strict-profile operations fail closed. |
| Stale authority and races | Attempt old-epoch/session operations, stale watches, lease reuse, restore rollback and concurrent revoke/action races at the protected resource boundary. |
| Recovery and compromise | Verify committed revocations survive failover and restart; test membership/key changes and unauthorized writes. Evaluate malicious replicas only with a separately specified BFT profile. |

Sources: https://raft.github.io/raft.pdf
https://etcd.io/docs/v3.7/dev-guide/api_reference_v3/
https://tikv.github.io/deep-dive-tikv/consensus-algorithm/raft.html

## Release-claim gate

Hardware-backed signing, attestation and consensus revocation must remain labeled
**planned** until their implementations and acceptance evidence are published.
Any future higher-assurance claim requires a deployment-specific threat model,
independent assessment, realistic fault/adversarial testing, supply-chain and
operational assurance, and acceptance by the relevant customer/accrediting body.
Neither these two roadmap entries nor a successful prototype test constitutes
military qualification, certification, or permission to claim operational readiness.
