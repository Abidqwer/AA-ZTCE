# AA-ZTCE enterprise SOC integration prototype

Run `bash run_enterprise.sh` for the complete local verification. Read
`COMPLIANCE.md` for the fourteen-component NIST AI RMF crosswalk and
`enterprise/DEPLOYMENT.md` for Terraform, Helm, credentials and deployment limits.

The enterprise edition adds bounded PII masking at the authorized data-release
boundary, a software signing-provider seam, explicit MITRE ATLAS enrichment,
a scoped workflow-management API and Go Terraform provider, and a single-replica
Helm sandbox. SPIFFE/SPIRE, OAuth token exchange, hardware key custody, ML-DSA
and ML-KEM remain planned; they are not claimed as working integrations.

The original archived engine remains unchanged in `published/`. The gateway uses
`runtime_engine.py`, a generated fork with two documented extension seams. No new
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
benchmark and multi-host deployment remain unperformed. The archive's published
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
scripted clients; live LLM execution requires the optional model endpoint. The baseline mode
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
deployment, or distributed systems verification. Agent stdio remains a permitted
channel to the trusted controller. Key custody in the Python processes is not hardware-backed.
The host/controller are trusted. The local TCP admin connection is not TLS; do not
expose this experimental adapter to an untrusted network. Connection-flood resilience
and admission fairness are not established.
