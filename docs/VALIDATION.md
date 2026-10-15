# Validation boundaries

The current engine is a local reference harness, not a production system. Read the root README and TIGHTENED_REPORT.md before interpreting pass counts.

## What is included

- Real Ed25519 signatures, X25519/HKDF session derivation and AES-GCM response encryption.
- Individually keyed scripted clients and a deterministic gateway.
- Admission checks against trusted task/group/environment records.
- Request-bound authority approval, replay checks, expiry and clearance/compartment checks.
- Current identity/task snapshot bindings, checkpoints, revocation and serialized lifecycle operations.
- Reproducible prior findings, 61 regression tests, stateful sequences, malformed inputs and thread trials.
- Z3 solver inputs/results for a mathematical model and explicit negative controls.

## What is not established

- Real agent peer discovery, hidden-motive extraction or semantic collective-risk detection.
- A live independent LLM interpreting the attack corpus.
- An integrated container/VM sandbox with a protected backing store and real tool network.
- Source-level refinement to the SMT model or a proof of cryptographic primitives.
- Cross-host revocation/cache consistency, external commit atomicity, queue cancellation or complete egress control.
- Effective cognitive confusion or computational distortion.
- Independent audit, certification, architectural worldwide uniqueness or comparative superiority.

Historical process exercises used separate workers with actual seccomp filters and resource limits. They were separate from the gateway and cannot establish an integrated isolated deployment. Historical live gateway exercises were directed by the assistant in the originating conversation, not a separately operated model benchmark.

## Reproduction and interpretation

Run `bash run.sh`. The scripts preserve both positive cases and known limitations. A passing limitation test confirms an exposure exists. A SAT weakened-design query is an expected counterexample, not a failed formal run. Original delivered outputs are in `evidence/`; regenerated root outputs carry the new execution time.

`evidence/ORIGINAL_EXPORT_SHA256_MANIFEST.json` records the original export's layout. `PUBLICATION_SHA256.json` records this repository's publication layout. The former must not be interpreted as a manifest of the current directory tree.

The five corrected findings are in `evidence/finding_reproductions.json`. The original unsafe implementation exists only under `before/` for those reproductions. Supported runtime administration must use the serialized methods; direct registry mutation is trusted harness/test behavior and would need prevention in a production deployment.
