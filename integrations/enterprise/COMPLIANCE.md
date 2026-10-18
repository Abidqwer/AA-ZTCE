# AA-ZTCE: NIST AI RMF evidence crosswalk

Author: Abid Yousef. Integration work: AI-assisted. Baseline: AI RMF 1.0 (2023).
This is a proposed function-level crosswalk, not a certification, legal opinion,
complete subcategory assessment, or statement that installing software satisfies
an organization's governance obligations. An assessor must approve applicability,
operating effectiveness, accountable owners, and residual risk for each deployment.

## The four functions in plain language

- **Govern:** Who is accountable, what rules apply, and who accepts remaining risk?
- **Map:** What is the agent meant to do, what can it touch, and who could be harmed?
- **Measure:** What evidence shows whether the controls work and where they fail?
- **Manage:** What action prevents, contains, or responds to the measured risk?

The proposed associations below are the author's interpretation of the NIST
functions. They do not imply NIST endorsement. Component names follow the original
architecture exactly; each association requires deployment-specific validation.

## Fourteen-component mapping

| ID | Architecture component | Supporting AI RMF functions | Local evidence / contribution | Remaining work and proposed owner |
|---|---|---|---|---|
| 01 | Individual identity and authority | Govern, Map, Manage | Registered agent keys, enabled state, clearance and compartment checks in `published/engine.py`; instance binding tests. | IAM owner must validate enrollment, accountable human ownership, offboarding and key custody. |
| 02 | Collective workflow assessment | Map, Manage | Explicit task/member/resource/destination registry and task-snapshot invalidation. | Workflow owner must approve purpose and combined effects; hidden intent and covert collaboration are not detected. |
| 03 | Connection and attack-surface inspection | Map, Measure | Configured environment/path evidence and local stale-evidence tests. | Platform owner must inventory real tools, controllers, data flows and unmediated channels; no automatic enterprise discovery. |
| 04 | Controlled sandbox boundaries | Manage, Measure | Separate processes and seccomp-denied file/socket/process operations in the Linux test adapter. | Platform security must validate its kernel/container controls and escape resistance; not a hardware enclave or multi-host boundary. |
| 05 | Impersonation resistance and hierarchical authority | Govern, Manage | Transport principal binding and a separate request-bound approval signer. | IAM/security owners must supply real organizational approvers, separation of duties and managed keys; full hierarchy not implemented. |
| 06 | Progressive guards A–B–C | Govern, Manage | Explicit policy gates and continuation restrictions illustrate the design. | Risk owner must define approved assurance thresholds and escalation procedures; automated adaptive scoring is not established. |
| 07 | Integrated checklist and decision | Govern, Measure, Manage | Admission/continuation tests and explicit unknown/stale evidence denials. | Control owner must assess evidence quality, decision coverage and exceptions against actual use cases. |
| 08 | Per-agent session cryptography | Manage, Measure | Ed25519 proofs, X25519-derived channels, AES-GCM responses, expiry/replay tests. | Cryptographic engineering must validate rotation, hardware custody, protocol review and recovery. Software signing remains the only implemented provider. |
| 09 | Zone/clearance enforcement | Map, Manage | Resource/action/compartment and destination checks with denial evidence. | Data owner must maintain classifications and permissions. Illustrative numbered zones are not official government classifications. |
| 10 | Injected verification | Measure, Manage | PASS/PENDING/FAIL checkpoints and identity/task/environment invalidation tests. | SOC and workflow owners must choose checkpoint placement and evaluate held-out false positives, false negatives and latency. |
| 11 | Discontinuity and fresh authentication | Manage, Measure | Revocation, stale grant rejection and signed SOAR containment tests. | Operations must test approved recovery and distributed propagation; released plaintext cannot be recalled. |
| 12 | Domain monitoring and response | Measure, Manage, Govern | ECS events, durable outbox, TLS/mTLS/HMAC SOAR, command/case correlation, controlled metrics. | SOC must validate actual SIEM indexing, playbook approval, retention, independent audit anchoring and response procedures. |
| 13 | Conditional defensive confusion | Map, Measure (research only) | Architecture proposal only; no claimed effectiveness. | Research and risk owners must evaluate safety and efficacy before any use. No implemented compliance credit. |
| 14 | Computational distortion | Map, Measure (research only) | Architecture proposal only; no claimed effectiveness. | Research and risk owners must establish bounded semantics, lawful use and independent review. No implemented compliance credit. |

## Evidence an enterprise should collect

| Function | Enterprise evidence beyond the prototype | Suggested accountable owner |
|---|---|---|
| Govern | Approved policy, RACI, risk acceptance, exception expiry, reviewer training, supplier assessment and periodic control review. | CISO / AI governance lead |
| Map | Workflow purpose, impacted people, data sensitivity, dependency inventory, threat model and trust-boundary diagram. | Workflow owner / data owner |
| Measure | Versioned test corpus, independent labels, incident reviews, false negatives, detection misses, load and failure tests, redaction accuracy by data type. | Assurance lead / SOC |
| Manage | Containment playbooks, approvals, incident drills, continuity/recovery procedures, retirement and reassessment decisions. | SOC lead / operations |

Evidence pointers: `results/`, `published/evidence/`, `docs/soc/openapi.json`,
`docs/soc/CONTROL_INTERFACE.md`, `enterprise/`, and `enterprise_verify.py`.
Results are local, scripted, AI-assisted evidence; not an independent audit.
The observed 0/240 context-rule false positives apply only to the scripted study;
40 permitted malicious reads remained outside the authorization detector's scope.
New masking tests do not retroactively change those historical results.

## Insurance: evidence supporting underwriting and incident review

AA-ZTCE can contribute records of approved scope, policy versions, denied actions,
revocation requests and control outcomes. Insurers may consider those records
alongside the enterprise's other controls. Premium changes, insurability, coverage,
claims acceptance and legal 'due care' depend on the policy, insurer and facts;
none is established by this software or its publication.

The current SOC journal is a **local, unkeyed SHA-256 hash chain**, not an
Ed25519-signed, immutable audit trail. It can support verification against a
separately trusted head. A privileged host attacker can rewrite the local history.
Signed agent requests are not signatures on journal entries. A future evidence
profile should sign canonical event batches, anchor heads outside the host, apply
independent retention controls, record trusted time, and document key compromise
and custody. Even that profile cannot prove that all relevant actions were logged.

Suggested paper language: "AA-ZTCE provides control-enforcement evidence that may
support insurer-specific underwriting and incident assessment. Any reduction in
premiums or losses requires independent, deployment-specific evidence."

## Sources and scope

- NIST AI RMF Core: https://airc.nist.gov/airmf-resources/airmf/5-sec-core/
- NIST AI RMF Playbook: https://airc.nist.gov/airmf-resources/playbook/
- Original architecture: `published/docs/ARCHITECTURE.md`.

NIST describes these functions as an ongoing risk-management process, not an
ordered software checklist. This mapping covers technical security contributions;
it does not assess all AI risks, including fairness, accessibility or societal impact.
