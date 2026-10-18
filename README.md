# AA-ZTCE enterprise SOC integration prototype

Run **`bash run_virtual_range.sh`** for the complete Linux live-AI range, preserved
verification, and hardware-emulator/consensus fault checks. Read `VIRTUAL_RANGE.md`
for setup, evidence and limitations. Run `bash run_enterprise.sh` for the earlier
enterprise checks alone. Read
`COMPLIANCE.md` for the fourteen-component NIST AI RMF crosswalk and
`enterprise/DEPLOYMENT.md` for Terraform, Helm, credentials and deployment limits.

The enterprise edition adds bounded PII masking at the authorized data-release
boundary, software and PKCS#11 Ed25519 signing providers, explicit MITRE ATLAS enrichment,
a scoped workflow-management API and Go Terraform provider, and a single-replica
Helm sandbox. The assurance profile adds TPM P-256 audit signing, fresh quote
appraisal, external witness receipts and three-node etcd authorization/revocation.
These mechanisms run with software TPMs and SoftHSM in the range; physical devices
and multi-host administration remain unvalidated. SPIFFE/SPIRE, OAuth token
exchange, ML-DSA and ML-KEM remain planned.

The original archived engine remains unchanged in `published/`. The gateway uses
`runtime_engine.py`, a generated fork with documented signing, data-release,
admission and operation hooks. No new
component claims immutable journal history, solved hidden intent, guaranteed
insurance savings, or an independently certified enterprise standard.

## SIEM / SOAR integration edition

Run **`bash run_soc.sh`** for the original verification plus SOC integration tests,
the controlled false-positive measurement, and dashboard/API asset generation.
Run **`bash run_soc.sh serve --directory soc_state`** to keep a local synthetic
gateway and mTLS SOAR endpoint running. No source edits or embedded credentials are required.

The five requested deliverables are under `docs/soc/` and `results/soc/`:

1. ECS event connectors (`soc/`), a native Splunk dashboard XML, Elasticsearch
   index template, and an offline correlation dashboard with captured events.
2. A 400-workflow false-positive study with all labels/outcomes, a technical
   note and PDF. Scripted results are not production FPR estimates.
3. OpenAPI 3.1 control contract, signed Python client, mTLS/HMAC response API,
   per-client action/agent scopes, persistent replay protection and command IDs.
4. A six-page positioning paper that separates preventive controls, SIEM,
   SOAR, SOC operations and compliance credentials.
5. A two-page BARQ pilot proposal for review. No outreach has been sent.

Protocol delivery was tested against local TLS collectors, not actual vendor
platforms. Synthetic EDR/identity events are clearly labeled. The live-model
range now runs locally with Qwen2.5-0.5B; multi-host deployment remains unperformed. The archive's published
core is unchanged; the runtime fork and adapters are explicitly separated.

`docs/soc/CONTROL_INTERFACE.md` documents signing, retries, capacity, latency,
trust boundaries and configuration commands. API keys, certificates and state
generated at runtime are private and are not included in the distributed package.

Additional technical verification of the archived Zenodo V0.2.1 software release:
https://zenodo.org/records/23387780

Run **`bash run_verification.sh`** on Linux with Python 3.10+ and libseccomp installed.
The script installs missing Python dependencies in its own virtual environment.
No containers, root permissions, production credentials, or manual code edits are needed.
If the kernel forbids seccomp, the process suite stops instead of claiming isolation.

Read **`results/VERIFICATION_REPORT.md`** and **`results/verification_results.json`** for actual results.
The exact original ZIP and an unchanged extraction are included. Original tests run
in a disposable copy. New adapter code is separate from the archived implementation.

`gateway.py` provides signed principal authentication, a private admin channel, bounded
JSON framing and a real-time clock. `agent_worker.py` holds an agent's private keys and
runs under `confinement.py`'s default-deny seccomp filter. The trusted controller
`verify.py` issues authority approvals and records test evidence. Agent workers are
structured tool clients; `virtual_range.py` drives them using actual model inference. The baseline mode
intentionally omits the transport-principal/admission-request binding; the hardened
mode enforces it, demonstrating finding F06 and an adapter-level mitigation.

Live-model tests are implemented using an OpenAI-compatible chat endpoint. The
optional environment variables are `AA_MODEL_BASE_URL`, `AA_MODEL_NAME`, and
`AA_MODEL_API_KEY` (or `OPENAI_API_KEY`). Without endpoint/model configuration, the
campaign is explicitly marked NOT_RUN. The model chooses a structured action, which
the confined worker then submits to the gateway. Only synthetic prompts/data are used.

Scope: separate local processes, OS syscall confinement, cryptographic access checks,
framing, replay, quotas, lifecycle changes and concurrent requests. This is not an
independent audit, production certification, complete network isolation, container
deployment or multi-host verification. The assurance suite exercises three local
etcd processes, leader failure, quorum loss and cross-gateway enforcement. Agent
stdio remains a permitted channel to the trusted controller. Lab gateway keys use
SoftHSM; TPMs are emulated. Worker and approval-authority keys remain software-held.
The host/controller are trusted. The local TCP admin connection is not TLS; do not
expose this experimental adapter to an untrusted network. Connection-flood resilience
and admission fairness are not established.

## Executed live-AI evidence

Open `results/virtual_range/AA_ZTCE_Live_AI_Report.html` and
`results/virtual_range/REPORT.md` for exact model calls, attack goals, control
denials, utility, residual releases and errors. These are authored synthetic cases,
not a population estimate or an independent safety grade. A separate scripted burst
and fault suite are reported separately. The adapter revokes sessions on
authenticated transport closure; the original archived core is preserved.

`assurance/DEPLOYMENT.md` and `assurance_cli.py --help` cover actual hardware,
witness and consensus configuration. Physical deployment requires device-specific
validation, approved enrollment inputs and separately administered trust services.
The earlier SOC positioning PDF describes the 0.4 baseline; this README and the
0.5 release notes document the newer assurance profile and live range.

Additional author-reported WSL2 measurements and their evidence limits are recorded
in `ENTERPRISE_ROADMAP.md`. `apply_empirical_evidence.sh` adds that section
idempotently to a local project while preserving its existing roadmap.
