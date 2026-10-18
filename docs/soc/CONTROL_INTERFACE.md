# Control interface and deployment contract

Profile: REST over TLS 1.2+ with mTLS and per-client HMAC-SHA256 signatures. The generated local sandbox enables mTLS. Local certificates/keys are development credentials, valid for 30 days; use a managed CA and separate server/client certificates for a real pilot. Keys are per deployment and client. No platform account was connected.

## Authentication and replay

Send X-AA-Key-ID, X-AA-Audience (the configured domain_id), X-AA-Timestamp (integer Unix seconds), X-AA-Nonce (32-128 lowercase hex), and X-AA-Signature (hex HMAC). Sign six lines, separated by LF with no trailing LF: METHOD; exact path including query; audience; timestamp; nonce; SHA256 of exact request bytes. For GET, hash the empty body. Timestamp tolerance is 90 seconds; nonces persist 180 seconds. Response identity is protected by verified TLS. Certificate trust does not grant an action: the HMAC client must also have that action and agent scope.

## Actions

POST /v1/actions requires command_id, case_id, action, agent_id, and session_id for session actions. revoke_session invalidates the named session. suspend_session sets PENDING and cannot reactivate a revoked session. require_reauth revokes every current session for the agent; it does not authenticate automatically. disable_agent disables identity and revokes current sessions. No action issues grants, credentials, or elevated permissions. Resume/re-enable requires the existing trusted administration/admission process.

## Retry and failure

Repeat a completed command with a NEW nonce and the same command_id/body to retrieve its result. A changed body with an old ID returns 409. Pending commands may be conservatively reapplied after interruption; all supported responses are monotone/idempotent containment operations. A successful response means the local gateway action completed, not that a remote queued tool action was canceled. Original sessions are in memory and do not survive a gateway restart. Audit/command records are durable; the system is not a distributed transaction.

## Event delivery

ECS projection: @timestamp, ecs.version, event.id/action/category/type/outcome/severity, observer.name, user.id and namespaced aa_ztce fields. SIEM exporters: Splunk HEC, Elasticsearch bulk, JSON HTTPS webhook, RFC 5424/5425 syslog over verified TLS. Local collectors validated protocol delivery; actual vendor instances were not available. HTTP acceptance is not proof of search indexing. Syslog TLS is write completion, not an application acknowledgment. Delivery is at least once; deduplicate event.id. The hash chain detects modifications when checked against a trusted head; an attacker controlling the host and replacing the whole chain is outside that guarantee. Archive and externally anchor the journal head.

## Capacity and time

The local audit journal stops accepting new events at max_events (default 100,000); event persistence failure prevents successful protected responses. SIEM outages retain the outbox and retry with bounded exponential delay. Monitor queue depth and provision retention/archival before the limit. Blocking audit writes can add access latency. Wall-clock integrity and clock jumps need operational controls. The SOAR API bounds concurrent request handlers at 32 and request bodies at 16 KiB. This is a tested integration candidate, not an independently audited production service.

## Latency

No contractual SLO is claimed. The local end-to-end mTLS/HMAC/action/SQLite measurements are in results/soc/soar_latency.json. A pilot acceptance target is p95 <= 1 second for local control acknowledgment under agreed load, with no successful protected continuation starting after the response ACK for a revoked session. Remote SIEM visibility and multi-host revocation need separate measured targets.

## Run without editing source

`bash run_soc.sh` installs missing Python dependencies and runs the entire local verification and asset-generation workflow. Linux/libseccomp is required for confined workers. `bash run_soc.sh serve --directory soc_state` starts a persistent synthetic sandbox, generates local credentials and prints its SOAR URL and initial session IDs. `bash run_soc.sh init --directory soc_state` initializes credentials only. `bash run_soc.sh add-sink` and `bash run_soc.sh attach` configure a chosen real endpoint and attach to an existing gateway configuration without source edits; use --help for their required arguments. Real SIEM endpoints, access tokens, trust roots, and approved deployment access are still required for a partner environment.

## Sources

- ECS event fields: https://www.elastic.co/docs/reference/ecs/ecs-event
- Splunk HEC event format: https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector
- Syslog: https://www.rfc-editor.org/rfc/rfc5424 and https://www.rfc-editor.org/rfc/rfc5425
