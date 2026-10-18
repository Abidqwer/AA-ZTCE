# Assurance and live-AI edition 0.5.0

This edition preserves the published core and earlier SIEM/SOAR, masking,
Terraform and Helm features. It adds actual Linux live-model execution and
optional hardware-provider/distributed assurance mechanisms.

## Added behavior

- One-command `run_virtual_range.sh`: local dependency extraction, pinned Qwen
  weights/llama.cpp runtime, existing tests, protocol/fault tests and AI campaign.
- Protected/unprotected comparison using actual structured model actions and
  synthetic effects; searchable standalone HTML, raw transcripts and JSON.
- PKCS#11 Ed25519 gateway signer with non-exportable key checks, hardware-slot
  requirement by default, wrong-PIN rejection and no software fallback.
- TPM P-256 audit signing and separate quote key; fresh context-bound remote
  appraisal against enrolled keys and approved PCR-snapshot fingerprints.
- Mutual-TLS external witness, durable sequential heads, pinned signed receipts,
  replay rejection, rollback/fork detection and fail-closed witness outages.
- Three-node etcd profile: scoped RBAC, authority epochs, session restrictions,
  conditional per-operation decision transactions and idempotent control commands.
- CLI for provisioning, quote capture, witness enrollment, profile attachment and
  external control. Test credentials are generated, never packaged.
- Adapter fix: authenticated transport closure invalidates local sessions and
  commits revocation to consensus when enabled. Original engine stays unchanged.

## Evidence and limits

Executed default evidence: 21/21 assurance checks; 131 real model calls over 38
cases; assurance attack goals 2/32, with six of six invalid-authority proposals
denied. Only three of six benign cases performed an operation; zero benign
operation denials were observed. All nine attacker-directed persona cases selected
noop, limiting boundary coverage. Separate scripted burst: 400/400 abuse denied,
100/100 legitimate allowed, about 3.39 RPS and 1.24s p95 on this machine.

Current machine-readable outcomes: `results/assurance/verification.json`,
`results/virtual_range/model_results.json`, `stress_results.json` and `REPORT.md`.
Real model inference is distinct from the scripted burst and protocol fault tests.
The corpus includes deliberate compromised-agent conditions; those test control
boundaries and do not estimate model compromise probability or production FPR.

The lab uses software TPMs/SoftHSM and separate local Linux processes. It does not
validate physical devices, Docker/WSL/Kubernetes deployment, independent witness
administration, Byzantine replicas or multi-cloud networking. Raft handles crash
faults. Per-operation ordering cannot recall plaintext or fence arbitrary external
tools. Worker and approval-authority keys remain software-held. Full hot rotation,
TPM NV-counter anti-rollback and manufacturer EK enrollment are not implemented.
Authorized business reads and encoded identifiers can remain exposed.

Earlier six-page SOC PDF and its measurements describe the 0.4 baseline below;
they are retained as historical evidence, not silently relabeled as new results.

---

# Enterprise alignment edition 0.4.0

## Delivered

- `COMPLIANCE.md`: exact fourteen-component architecture crosswalk to NIST AI RMF
  functions, evidence, accountable owners, research gaps and insurance wording.
- `runtime_engine.py`: generated fork preserving the published source; software
  signing-provider seam and post-authorization, pre-encryption data-release hook.
- `enterprise/masking.py`: bounded UTF-8 SSN/email/Luhn-valid card masking, audit
  counts without raw values, and blocked releases on scanner errors.
- `enterprise/taxonomy.py`: explicit, evidence-referenced ECS/ATLAS enrichment.
  Verified catalog: AML.T0052 means Phishing, not unauthorized tool execution.
- Scoped, revision-checked workflow REST API plus Go Terraform provider managing
  definitions only. Neither component enrolls identities or issues access grants.
- Helm chart, container recipe, managed-config runtime and one-command sandbox
  deployment script. Existing local verification remains a single installer.
- SPIFFE/SPIRE, RFC 8693, hardware key custody and PQC roadmaps with acceptance gates.
- Revised six-page SOC positioning paper explaining evidence value and claim limits.

## Executed evidence

- Existing separate-process verification: **53/53** expected outcomes.
- Existing SOC integration verification: **45/45** expected outcomes.
- Enterprise suite: **18 passed, 1 skipped** (19 selected tests).
- Go 1.24.2 provider compiled; schema validation and real HTTPS/mTLS/HMAC gateway
  create/read/update/delete callbacks and revision-conflict tests passed.
- Helm 3.17.3 lint and rendered YAML checks passed.
- OpenAPI 3.1 validation passed, including workflow CRUD.
- Source-only checkout prepared reference files from the existing repository and
  passed all 53 verification checks without an original archive ZIP.
- Original source/evidence manifest still matches all 61 listed files.
- Controlled 400-workflow measurement is unchanged: 0/240 context-rule benign
  alerts, 40 in-scope malicious reads not detected by authorization. New redaction
  examples do not revise that historical experiment or demonstrate real-world FPR.

## Explicitly unperformed

Terraform CLI plugin lifecycle: host forbids AF_UNIX sockets required by its
standard Linux go-plugin transport. Provider callback integration is tested;
normal-host CLI negotiation still requires validation. The suite reports a skip.

Docker image build, Kubernetes scheduling/storage/network enforcement, live SIEM
indexing, real agent models, production load, SPIFFE, OAuth exchange, HSM/TPM/KMS,
ML-DSA and ML-KEM were not executed. No independent audit or certification exists.

## Material limitations

PII detection covers a narrow set of formats. Encoded and contextual sensitive
information, business secrets and inferred data can pass. Authorization and
redaction do not determine hidden intent or retract released data.

The current audit journal is an unkeyed local SHA-256 chain. It is not an immutable
or Ed25519-signed journal. No insurance premium reduction, guaranteed coverage,
legal due-care finding, complete AI RMF satisfaction, or enterprise-standard
adoption is claimed.

Automatic approval review rejected copying the original publication ZIP into
GitHub as beyond the requested source-change scope. The source-only draft omits
that archive and the compiled binary. It uses existing manifest-verified repository
files locally. The complete downloadable package retains its original archive.
