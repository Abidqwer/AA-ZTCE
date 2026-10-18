# SOC integration delivery - 19 October 2026

The package implements the five requested work products. It is a technical integration candidate, not an independent audit or a connected customer SOC deployment.

1. **Working ECS SIEM connector and dashboard:** Splunk HEC, Elasticsearch bulk, JSON HTTPS and syslog TLS. Local collector protocol tests passed. Native Splunk XML and Elasticsearch template are provided. The offline HTML dashboard joins captured AA-ZTCE events with explicitly synthetic EDR/identity telemetry.
2. **Measured false-positive note:** 400 scripted workflows; naive threat-alert FPR 50%, context-rule observed FPR 0/240 benign workflows. All 40 permitted malicious-goal cases were missed; overall malicious recall 75%. This is a narrow deterministic study, not a production FPR claim.
3. **SOAR contract:** OpenAPI 3.1, REST with mTLS/HMAC, domain audience, nonce/timestamp replay checks, persistent command IDs and per-client action/agent scopes. Suspension, revocation, fresh authentication and identity disablement are implemented.
4. **Positioning paper:** Five pages, with a comparison table. AA-ZTCE complements SOC/SIEM/SOAR and does not establish compliance credentials.
5. **BARQ pilot proposal:** Two pages with sandbox scope, acceptance targets and division of labor. No partner outreach or commitments were made.

## Validation

- Existing verification: 53/53 expected checks, including original-suite execution checks.
- SOC integration: 45/45 expected checks.
- mTLS/action latency: 21 local samples; median 8.65 ms; p95 12.11 ms. No production SLO is claimed.
- OpenAPI validated, action schema positive/negative examples checked, Splunk dashboard XML parsed.
- Dashboard filter and NDJSON download logic checked with a DOM stub. Rendered-browser acceptance was not performed because a browser binary could not be downloaded in this environment.
- Persistent sandbox startup, signed CLI revocation and preservation of existing gateway config were smoke-tested.
- Five-page paper, two-page proposal and two-page measurement note were rendered and visually reviewed.

## Run

`bash run_soc.sh` runs the complete local test workflow with dependency installation if needed. `bash run_soc.sh serve --directory soc_state` starts the persistent synthetic sandbox. Linux and libseccomp are required. External SIEM/SOAR platform access, managed certificates and deployment credentials are not supplied by this package. See docs/soc/CONTROL_INTERFACE.md.

## File guide

- docs/soc/AA_ZTCE_SOC_Positioning_Paper.pdf
- docs/soc/AA_ZTCE_False_Positive_Technical_Note.pdf
- docs/soc/BARQ_AA_ZTCE_Pilot_Proposal.pdf
- docs/soc/openapi.json
- docs/soc/SOC_Correlation_Dashboard.html
- docs/soc/splunk-dashboard.xml
- docs/soc/elastic-index-template.json
- results/soc/ (logs, ECS events, full labels and results)
- soc/ (all connector/control source), soc_cli.py, soc_runtime.py

The prior implementation, tests, documents, archived original ZIP and optional live-model runner remain included. The published reference core is unchanged. Live-model and multi-host validation remain unperformed. No hosting, GitHub or Zenodo publication was changed.
