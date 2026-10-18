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
