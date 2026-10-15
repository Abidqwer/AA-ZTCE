# AA-ZTCE
Assurance-driven security architecture for autonomous multi-agent systems

**Autonomous Agent Zero-Trust Cryptographic Enclave**  
**Proposal originator:** Abid Yousef · **Reference implementation:** 0.2.0 · **Status:** research prototype

AA-ZTCE proposes a coordinated process for determining the security assurance required before granting an autonomous agent access, enforcing that access, and reassessing it throughout execution. Agents are evaluated individually, as participants in a collective workflow, and in relation to their surrounding execution environment and communication paths.

**This repository contains an executable local reference core, self-authored adversarial tests and Z3 checks of a mathematical abstraction. It is not a certified product, an independently audited system or a demonstrated globally unique architecture.** The word *enclave* in the name does not establish the use of a hardware trusted execution environment.

## Architecture

![AA-ZTCE operating model](docs/diagrams/02_operating_model.svg)

**Determine required assurance → evaluate applicable evidence → establish controls and recheck → decide access → continuously verify and respond.**

Checks are selected according to the required assurance and current conditions. Every applicable mandatory condition must pass; unrelated positive checks cannot compensate for a critical failure.

- [Architecture explanation and fourteen control components](docs/ARCHITECTURE.md)
- [Advanced visual architecture PDF](docs/AA-ZTCE_Advanced_Visual_Architecture_v2.pdf)
- [Tightened implementation report](docs/TIGHTENED_REPORT.md)
- [Internal verification PDF](docs/AA-ZTCE_Tightened_Internal_Verification.pdf)

## Run the implementation and checks

Requires **Python 3.10+**. From a checkout of this repository:

```bash
bash run.sh
```

The script uses the selected Python interpreter. If `cryptography` or `z3` is missing, it creates a local virtual environment and installs the pinned requirements. Installation requires network access and Python's venv/pip support.

It executes the regression suite, old/new finding reproductions, seeded stateful campaign, real thread schedules, Z3 queries and scripted malicious tool-action simulations. It exits nonzero if a required assertion or expected solver result fails.

Outputs are regenerated in the repository root. The original published run is preserved under [evidence/](evidence/). Rerunning does not replace that published snapshot. The model checker also writes SMT inputs under [smt_queries/](smt_queries/).

## Recorded results

| Check | Recorded outcome |
|---|---|
| Original regression suite | 61 passed, including three explicit limitation demonstrations |
| Stateful campaign | 200 seeded episodes; 5,000 actions |
| Dynamic assertions | 2,159 passed; multiple assertions may concern one action |
| Concurrent-update trials | 120 passed across six lifecycle-update types |
| Malformed envelopes | 57 controlled denials |
| Z3 model checks | 20 expected outcomes: 14 UNSAT, two legitimate SAT witnesses, four weakened-design SAT counterexamples |
| Scripted adversarial tool actions | 14 out-of-scope actions denied; one benign and one maliciously motivated in-scope read allowed |

These are finite, internally generated results, not measured overall attack-prevention rates. An UNSAT result excludes the specified counterexample under the model's assumptions; a SAT negative control deliberately exhibits a weakened design's failure.

See [dynamic results](evidence/dynamic_results.json), [formal results](evidence/formal_results.json), [adversarial results](evidence/adversarial_results.json), and the [regression log](evidence/regression.log).

## What was tightened in 0.2

Five issues were reproduced against the previous harness and corrected:

1. Existing grants survived an authoritative task-purpose change.
2. A replacement instance registered under the same name could trigger an encrypted release using an old grant.
3. An identity update could commit during an in-flight authorization/release sequence.
4. Malformed input raised an unhandled exception.
5. Pending challenges were unbounded for one agent.

Corrections add task-snapshot and identity-generation/key bindings, serialized supported lifecycle updates, bounded request schemas and state budgets. [Before/after evidence](evidence/finding_reproductions.json) and the [complete source diff](docs/ENGINE_CHANGES.diff) are included.

The old implementation is isolated under [before/](before/) for reproduction only. **The current runtime is the root `engine.py`.**

## Scope and remaining limitations

- Four scripted client objects and the gateway execute locally. This is not an adversarially isolated multi-agent deployment.
- Environment and collective-assessment records are trusted simulated inputs. Actual peer discovery, hidden-intent extraction and remote attestation are not implemented.
- Attack text is associated with scripted malicious tool actions; no independent live LLM consumes the injection corpus. Cognitive prompt-injection robustness is therefore unverified.
- Cryptographic operations are real, but the custom harness protocol is not a reviewed Signal/WhatsApp protocol. Production key custody, persistence and transport are not supplied.
- A process lock orders local updates and releases. Distributed revocation, cache races and external queued transactions remain unverified.
- Approved plaintext can be retained. Malicious operations remaining within approved scope can pass. False trusted evidence can lead to admission.
- Z3 checks an abstraction, not verified Python source, cryptographic primitive security, operating-system isolation or model reasoning.
- Higher-layer confusion/manipulation and computational distortion remain experimental proposals; their effectiveness is not established.

Historical syscall-confinement exercises were separate from the gateway and do not establish integrated VM/container isolation. See [validation scope](docs/VALIDATION.md).

## Independent review

[Audit scope and handoff](docs/AUDIT_SCOPE.md) cover token lifecycle, cryptographic validation, policy evaluation, identity rotation, task freshness and update ordering. **No independent audit is complete or scheduled.**

Public issue reports and reproducible technical criticism are welcome. Do not include private keys, credentials or real sensitive data in reports.

## Citation, attribution and publication

Use [CITATION.cff](CITATION.cff) to cite this version. Original architecture ideas and clarifications were supplied by **Abid Yousef**. Drafting, implementation, diagrams and internal testing were AI-assisted. There is no external endorsement or certification.

The proposal is documented in [ARCHITECTURE.md](docs/ARCHITECTURE.md); source anchors and related work appear in [REFERENCES.md](docs/REFERENCES.md). Worldwide uniqueness and superiority over existing architectures have not been established.

**License:** a project-wide software license has not yet been selected. No additional license grant is declared by this README.

[Publication file hashes](PUBLICATION_SHA256.json) identify the initial source/evidence snapshot; the manifest excludes itself.
