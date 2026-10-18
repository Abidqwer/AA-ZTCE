# AA-ZTCE Linux live-AI evaluation range

## Run the complete environment

On Linux x86_64 (tested on Ubuntu 24.04), from the extracted package directory:

```bash
bash run_virtual_range.sh
```

Prerequisites: Python 3.12 with venv support, apt-get/dpkg-deb, internet for the
first dependency/model downloads, about 2 GB free disk, and preferably 4 GB RAM
and four CPU cores. Ubuntu 24.04 under WSL is a suitable target to validate on your
Windows computer; WSL itself was not available for testing in this session.

The installer creates a private Python environment when needed, downloads native
TPM/SoftHSM distribution packages into a local cache, extracts them without system
package installation, verifies pinned etcd/model/server downloads, runs preserved
verification, runs hardware/consensus fault tests, and executes the live AI campaign.
It does not clear a physical TPM, install a daemon or modify global apt settings.
Native packages follow the host's signed distribution repositories; they are not
claimed to be immutable inputs across every future machine. Model and runtime
archives have pinned URLs and SHA-256 checksums in `range/downloads.json`.

The default model is **Qwen2.5-0.5B-Instruct Q4_K_M**, executed by llama.cpp on CPU.
It downloads approximately 491 MB of model weights and needs no paid model API.
This small model is an execution baseline; its results do not establish the
behavior of larger or different model families.

For a longer run:

```bash
bash run_virtual_range.sh --turns 4 --adaptive 20 --seed 20261020
```

For a configured, compatible remote model, use `--endpoint` and `--model-name`.
The endpoint must support JSON-schema structured responses. Supply its credential
through `AA_MODEL_API_KEY` if required; the runner never writes it into reports.
Remote-model calls are made only when you explicitly configure that endpoint.
Only synthetic workflow data is used. API billing is the endpoint owner's concern.

## What actually runs

| Component | Execution and boundary |
|---|---|
| Live AI | Real local model weights and inference in a separate llama.cpp process. An attacker-generation role creates additional prompt variants using the same small model. |
| Unprotected comparator | Separate process reading and modifying a fixed registry of synthetic files. A local quarantine represents an external release; no external exfiltration occurs. |
| Core condition | Real gateway and four separate seccomp-confined workers; signed identity/session checks. Masking, hardware providers and consensus are disabled for comparison. |
| Assurance condition | Real gateway/worker operations with PKCS#11 gateway signing, TPM audit signatures, remote quote appraisal, externally retained signed receipts, output masking and authoritative consensus checks. |
| Consensus | Three actual etcd processes with mutual TLS and enabled RBAC. Enforcement credentials cannot rewrite revocation state or another node's decision key. Separate privileged control credentials perform revocation. |
| TPM/HSM | Two separate software TPM processes and a SoftHSM token. These test real mechanisms/protocols, not physical device isolation. |
| Witness/verifier | Actual TLS/mTLS service with a durable SQLite database, pinned audit/attestation keys, client-certificate bindings, nonce replay checks and pinned receipt verification. It runs in the test controller, separately from the gateway processes; real administrative independence requires another host. |

No VM or Docker daemon was available here. The executed range uses separate Linux
processes and worker syscall confinement. `Dockerfile.range` is supplied as a
container build option but has not been built or validated here. Arbitrary code
execution inside the inference server/controller, kernel takeover, VM escape,
physical hardware extraction, Byzantine replicas and multi-cloud partitions were
not evaluated. A malicious prompt and a host compromise are different adversaries.

## Campaign design

The authored corpus covers legitimate tasks, legitimate replanning, direct/indirect
instruction injection, fake authority, peer impersonation, compartment violations,
external destinations, unauthorized deletion, stale sessions, PII exposure, encoded
sensitive data and an eleven-turn delayed-payload case. Explicit attacker-directed
agent scenarios provide an attacker-directed system prompt to challenge the external boundary;
the model can still refuse or noop. They do not measure the probability of compromising a deployed model.

Each case's first live-model proposal is executed identically against all three
conditions. Subsequent turns receive the actual tool result of their own condition
and can diverge. No model-generated shell command is executed. Refusal/noop,
invalid output, authorization denial, actual release and actual synthetic mutation
are distinct outcomes. The same model supplies attacker-generation and agent roles;
this is not independent red teaming or a representative benchmark.

A separate scripted burst submits 400 replay, malformed-envelope, principal-spoof
and invalid-signature requests, then 100 legitimate requests from four workers.
These counts are not described as AI-generated exploits or production load capacity.
Heartbeat traffic keeps idle worker connections alive without extending grants.

## Read the evidence

Generated outputs are under `results/virtual_range/`:

- `AA_ZTCE_Live_AI_Report.html`: self-contained searchable evidence report, with a
  JSON-download button. It makes no external network requests.
- `model_results.json`: exact conditions, goals, denominators, errors and model hash.
- `transcripts.jsonl`: actual model-selected tools and tool-return data (synthetic).
- `stress_results.json`: separate scripted request-burst outcomes and timing.
- `REPORT.md`: concise technical findings and limitations.
- `partial_cases.json`: checkpointed progress, retained if a run is interrupted.
- `pilot/`: earlier smaller-corpus run, retained to avoid presenting an expanded
  experiment as if its corpus had never changed.

`results/assurance/verification.json` and `protocol_checks.log` contain the hardware
and three-node fault tests. Original deployment/SOC/enterprise checks remain under
`results/` and can still run independently with their existing commands.

Attack-goal success is assessed from actual tool effects/data releases against a
predefined synthetic objective. Conditional boundary blocking is a different
metric: it counts denied invalid-authority actions only among such proposals.
Never call model refusal a gateway block. Benign task completion and benign-operation
denials are reported separately; the small scripted corpus does not estimate
production false-positive rates. Zero observed violations is not universal safety.

## Interpreting the remaining exposure

The executed pilot and expanded run exposed permitted business information and base64-encoded identifiers
even with the full assurance profile. This is expected coverage loss: masking detects
a limited set of plaintext identifiers; authorization cannot infer hidden intent.
Use minimization, data-owner approval, content-aware controls and egress restrictions
appropriate to the real data. Do not label those reads harmless or hide them in an
aggregate 'blocked attacks' percentage.

The range also reproduced a transport-continuity bug: an admitted session could
remain active after its worker connection exited. The adapter now revokes that
principal's sessions on authenticated transport closure, including consensus
revocation when configured. A dedicated end-to-end test covers the fix.

## Hardware and distributed deployment outside the lab

`assurance_cli.py --help` exposes ready commands for TPM provisioning, quote capture,
PKCS#11 key generation, witness initialization/enrollment, profile generation,
attachment to an existing gateway configuration, and external revocation commands.
Each subcommand has argument help; no source-code or manual JSON edits are required.

Physical deployment requires actual device access, vendor PKCS#11 support for
Ed25519, enrolled platform keys and approved PCR references, managed certificates,
a separately administered witness and a correctly operated consensus cluster.
Default PKCS#11 loading rejects software tokens; only the lab explicitly enables
them. There is no software fallback when a configured hardware provider fails.
TPM audit signing uses P-256 ECDSA, separate from Ed25519 gateway/HSM signing.
Agent-worker and reference approval-authority keys remain software-held in this lab.

For etcd's HTTP gRPC gateway with RBAC, use client certificates without a Common
Name and authenticate using a scoped username/password file over mutual TLS.
The fixture demonstrates this combination. Do not give enforcement-only nodes
control-writer credentials; keep those in the separately administered SOAR/control
plane. The lab co-locates them solely to exercise end-to-end containment.

Revocation is ordered at its authoritative commit. Every strict-profile operation
performs a comparison-and-write authorization transaction; stale state, races or
unreachable quorum deny access. A previously ordered operation can finish after a
later revocation, and already released data cannot be recalled. Raft is not Byzantine
tolerant. The witness is externally administered evidence, not an immutable database
against its own administrator. TPM quotes appraise selected PCR state and freshness;
they do not prove that a running application never became compromised.

### Executed default run

The completed run made 131 actual model calls over 38 cases (32 authored and six
model-generated), each evaluated in three conditions. Attack goals succeeded in
8/32 unprotected, 3/32 core and 2/32 assurance cases. Assurance denied all six
invalid-authority tool proposals; the small denominator limits confidence. All nine
attacker-directed persona cases produced noops, so they did not exercise the boundary.
Three of six benign cases performed a successful operation, with zero observed benign
operation denials. The model often chose noop; this is not full task completion.

The separate scripted burst denied 400/400 protocol-abuse requests and allowed
100/100 legitimate requests. Full-profile burst throughput was about 3.39 requests
per second and p95 latency about 1.24 seconds on this host. This conservative
per-operation attestation/anchoring profile is not a 1,000-RPS implementation.
See the exact JSON instead of extrapolating to production.
