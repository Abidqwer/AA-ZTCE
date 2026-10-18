#!/usr/bin/env bash
set -euo pipefail
if [[ $# -gt 1 ]]; then echo 'Usage: bash apply_empirical_evidence.sh [project-directory]' >&2; exit 2; fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -eq 1 ]]; then
  TARGET="$1"
elif [[ -d "$HOME/aa-ztce-enterprise/AA_ZTCE_Deployment_Verification" ]]; then
  TARGET="$HOME/aa-ztce-enterprise/AA_ZTCE_Deployment_Verification"
elif [[ -f "$SCRIPT_DIR/gateway.py" ]]; then
  TARGET="$SCRIPT_DIR"
elif [[ -f "$PWD/gateway.py" ]]; then
  TARGET="$PWD"
else
  echo 'Project not found. Pass its directory as the single script argument.' >&2; exit 1
fi
python3 - "$TARGET" <<'PYTHON_EVIDENCE'
from pathlib import Path
import datetime
import sys
root=Path(sys.argv[1]).expanduser().resolve()
if not (root/'gateway.py').is_file():raise SystemExit('Target does not contain gateway.py; no files changed.')
target=root/'ENTERPRISE_ROADMAP.md'
source=target if target.exists() else root/'enterprise/ROADMAP.md'
if not source.is_file():raise SystemExit('Existing roadmap missing; no files changed.')
old=source.read_text(encoding='utf-8')
section='<!-- AA-ZTCE:WSL2-EVIDENCE:BEGIN -->\n\n---\n\n## Empirical Verification Evidence — User-Reported WSL2 Run\n\n**Reported test date:** October 19, 2026.  \n**Reported environment:** Local WSL2, Python 3.12, gateway at `127.0.0.1:8765`.  \n**Evidence status:** Results supplied by the author in conversation. The load script,\nraw request/response classifications, gateway configuration, resource metrics and\ncomplete test logs were not supplied for independent reproduction. These results\nare separate from the packaged local Qwen/assurance experiment.\n\n### 1. Concurrent TCP load — 5,000 reported successful requests\n\n| Reported measurement | Value |\n|---|---:|\n| Client concurrency | 1,000 threads |\n| Requests | 5,000 |\n| Client-reported successes / failures | 5,000 / 0 |\n| Throughput | 1,481 requests/second |\n| Median latency | 16.12 ms |\n| p99 latency | 3,092.02 ms |\n| Described traffic | Benign, PII-release attempts and Base64 evasion |\n\nThe author calls this the “1,000-agent swarm / wipeout test.” Concurrency of\n1,000 client threads does not establish 1,000 authenticated, admitted agent\nidentities or 1,000 simultaneously outstanding requests. A successful TCP exchange\nor JSON reply can contain an authentication rejection; it is not necessarily a\nsuccessful authorized operation or prevented malicious release. The success\npredicate must be published before interpreting this as security effectiveness.\n\nThe reported run supports a client-observed completion measurement under its\nspecific configuration. Its high p99 shows tail latency, but does not establish\nwhether the cause is the Python GIL, domain locks, SQLite/WAL contention, thread\nscheduling, network queues, retries or client-side limits. Attribution requires\nprofiling and a defined latency window. No connection-drop conclusion should\nexceed the client\'s measured failure definition.\n\nNginx edge controls and an asynchronous Kafka audit pipeline are candidates for\nseparate evaluation; these numbers do not prove either is necessary or sufficient\nfor sub-100ms p99. Audit decoupling must specify durability, backpressure and the\nmaximum unanchored exposure. It must not silently weaken the full assurance\nprofile\'s fail-closed witness receipt requirement. Do not compare 1,481 RPS with\nthe packaged full-profile burst without matching authentication, attestation,\nconsensus, anchoring, concurrency and work-per-request settings.\n\n### 2. Enterprise suite — 17 passed, 2 skipped, as reported\n\nThe author reports Go/Terraform binaries absent on this host. Preserve the complete\nrunner output to establish exactly which tests skipped and which code revision ran.\nThe enterprise suite includes unit-level checks and live-gateway integration;\nit is not uniformly 19 external tests of one already-running gateway endpoint.\n\nReported checks, consistent with checks present in the supplied suite:\n\n- Bounded plaintext PII masking before encrypted delivery and worker decryption.\n- Base64-encoded identifiers explicitly remain an unmasked known miss. This example\n  does not independently validate an earlier 9% attack-success estimate.\n- Unauthorized operations do not invoke the DLP scanner. This avoids that scanner\'s\n  work on denied operations; it does not demonstrate general DoS protection.\n- Approved workflow/task changes invalidate grants bound to an earlier task snapshot.\n- Tested masking audit records exclude the raw PII used in those fixtures. This is\n  not a guarantee that every possible log path is free of sensitive information.\n\n### 3. Transport authentication — application challenge-response\n\nThe author reports a raw JSON TCP attempt returning:\n\n```json\n{"ok": false, "error": "transport authentication failed"}\n```\n\nIn the supplied `gateway.py`, the worker transport sends a fresh nonce, reads and\nJSON-parses the bounded hello, then verifies the registered agent\'s Ed25519 proof\nbound to that nonce. The rejection above is consistent with failed application\ntransport authentication. It is **not evidence of an mTLS handshake**, nor of\nrejection before JSON parsing. Mutual TLS is used by separately configured SOAR,\nwitness and consensus services; that does not make the worker TCP listener mTLS.\n\nThis observation demonstrates rejection of that unauthenticated attempt. It does\nnot by itself establish resistance to connection floods, malformed JSON, signature\nverification exhaustion or prompt injection. Those require separately classified\nexperiments, resource measurements and actual protected-operation outcomes.\n\n### Acceptance evidence needed to strengthen these claims\n\nRetain the script and its success predicate; exact source hash and enabled\nconfiguration with secrets removed; per-class allow/deny and actual data-release\noutcomes; client/server timing definitions and latency samples; concurrent\nconnections and admitted identity counts; CPU, memory, queue/lock and journal\nmetrics; repeats across load levels; and the full enterprise test output.\nA measured result can then be independently rerun without replacing the existing\nhistorical measurements or treating author-reported evidence as certification.\n\n<!-- AA-ZTCE:WSL2-EVIDENCE:END -->\n'
begin='<!-- AA-ZTCE:WSL2-EVIDENCE:BEGIN -->'
end='<!-- AA-ZTCE:WSL2-EVIDENCE:END -->'
if begin in old or end in old:
    if old.count(begin)!=1 or old.count(end)!=1 or old.index(end)<old.index(begin):
        raise SystemExit('Ambiguous existing evidence markers; no files changed.')
    start=old.index(begin);stop=old.index(end)+len(end)
    updated=old[:start]+section.rstrip('\n')+old[stop:]
else:
    updated=old.rstrip()+'\n\n'+section
if target.exists() and old==updated:
    print('ENTERPRISE_ROADMAP.md already contains this evidence; no changes needed.')
else:
    if target.exists():
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        backup=target.with_name(target.name+'.backup-'+stamp)
        backup.write_bytes(target.read_bytes());backup.chmod(target.stat().st_mode & 0o777)
    temporary=target.with_name(target.name+'.tmp')
    temporary.write_text(updated,encoding='utf-8')
    if target.exists():temporary.chmod(target.stat().st_mode & 0o777)
    temporary.replace(target)
    print('ENTERPRISE_ROADMAP.md updated; previous content preserved and reported evidence clearly qualified.')
PYTHON_EVIDENCE
