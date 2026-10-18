# Run and review the enterprise integration prototype

This preserves the archived release in `published/`. `runtime_engine.py` is an
explicit generated fork adding only a signing-provider seam and a post-authorization,
pre-encryption release hook. Rebuild it with `python enterprise/build_runtime.py`.
Gateway masking is enabled by default. It can reduce output utility and does not
sanitize every kind of sensitive information; see `ROADMAP.md`.

## Local verification: one command

```bash
bash run_enterprise.sh
```

The installer checks Python dependencies, runs original/process/SOC checks,
regenerates SOC assets and runs enterprise checks. Optional Go/Terraform/Helm
checks run when those tools are installed. A missing optional tool is reported,
not silently counted as a pass. Linux libseccomp is required for confined workers.
The complete cluster/dependency supply chain is not certified by local tests.

Start the existing synthetic runtime with `bash run_soc.sh serve --directory soc_state`.
It creates local development credentials, not enterprise PKI. The API has no new
automatic enrollment, approval or privilege-granting endpoint.

## Terraform provider

The source is in `terraform-provider-aaztce/`; `go.mod` and `go.sum` record resolved
dependencies. A Linux/amd64 binary is included in the downloadable bundle. Build
for your own environment with Go 1.23 or later:

```bash
cd terraform-provider-aaztce
go mod verify
go test ./...
go build -buildvcs=false -trimpath -o terraform-provider-aaztce
```

For local development, set `TF_CLI_CONFIG_FILE` to a file containing an absolute
path to that directory (the source address is a development address, not a
published Terraform Registry entry):

```hcl
provider_installation {
  dev_overrides {
    "local/abid/aaztce" = "/absolute/path/terraform-provider-aaztce"
  }
  direct {}
}
```

Under a dev override, use `terraform validate`, `plan`, and `apply` directly;
`terraform init` may try to find an unpublished Registry package.

```hcl
terraform {
  required_providers {
    aaztce = { source = "local/abid/aaztce" }
  }
}
provider "aaztce" {
  endpoint      = "https://localhost:8443"
  key_id        = "workflow-admin"
  key_file      = "/secure/operator.key"
  ca_file       = "/secure/server-ca.pem"
  cert_file     = "/secure/client.pem"
  cert_key_file = "/secure/client-key.pem"
}
resource "aaztce_workflow" "finance_agent" {
  name         = "finance_agent"
  agents       = ["A"]
  resources    = ["inventory"]
  destinations = ["internal"]
  purpose      = "inventory-analysis"
}
```

Use real listener coordinates/certificate paths. The SOAR client entry must contain
`actions: ["manage_workflows"]`, explicit `agents`, `resources`, and `destinations`
allowlists, and its existing `key_file`. Existing default SOC clients do not have
workflow-management permission. Restart after authorized configuration changes.
A Terraform declaration configures authority limits; independent approval is still
required to admit an agent. Purpose must match the admitted request exactly.

Workflow API: GET/PUT/DELETE `/v1/workflows/{name}` using the existing TLS/mTLS/HMAC
profile. PUT sends `agents`, `resources`, `destinations`, `purpose`, and integer
`expected_revision` (0 to create). DELETE sends `expected_revision`. GET returns
those definition fields, `id`, and integer `revision`. Stale revisions return 409;
refresh and review changes before applying. Built-in `stock` is reserved. Invalid
input is 400; missing role/target/data scope is 403; absent GET is 404. Definitions
survive restart, but original session state does not. Destroy removes the workflow
and revokes its current sessions; it does not cancel external completed actions.
Interrupted create can require an explicit `terraform import` after inspection.

## Helm sandbox prerequisites

1. A Linux Kubernetes sandbox with seccomp support and a NetworkPolicy-enforcing
   CNI, a functioning default StorageClass, Docker, kubectl, Helm, and registry
   credentials. No Kubernetes cluster was available for the local verification.
2. A pre-provisioned Kubernetes Secret containing `soc-config.json`, `server.pem`,
   `server-key.pem`, `client-ca.pem`, and each configured client's operator key.
   Keys must be mounted at the exact configured paths under `/credentials/`.
3. In `soc-config.json`, set `state_dir` to `/state`, `domain_id` to `Domain-X`,
   `max_events` to an agreed capacity, `siem_sinks` to approved destinations, and
   `soar` host/port to `0.0.0.0`/8443. Set `cert_file`/`key_file`/`client_ca` to the
   managed mounted paths. Configure client scopes as above. Server SANs must match
   the Service DNS name; client certificates must chain to the client CA.
4. Label authorized in-namespace SOC client pods `aa-ztce-client=true`. The chart
   denies egress by default. Supply explicit `networkPolicy.egress` rules for any
   actual SIEM and required DNS; no external data export works until allowed.

Then run:

```bash
AA_ZTCE_IMAGE=your-registry/your-aaztce \
AA_ZTCE_SECRET=your-managed-credentials \
AA_ZTCE_NAMESPACE=your-existing-sandbox \
bash deploy_sandbox.sh
```

The command builds/pushes an image and installs the chart in your selected cluster.
It requires real values; it does not create a cluster, private CA, registry or
partner connection. A reviewer should pin an approved base-image digest and sign/
scan the built image. The supplied Python image tag and Debian package resolution
are not immutable build inputs. Secrets must be managed outside Terraform state.

The chart has one replica/Recreate, PVC storage, nonroot UID 10001, dropped
capabilities, no service-account token, read-only root and a writable bounded /tmp.
Readiness/startup probes only check TCP listener availability, not successful
cryptographic authentication or downstream SIEM health. Four local scripted
workers are demonstration workloads; their RPC stays inside the pod. Grants
expire after 60 seconds and are not silently renewed. PVC is retained on Helm
uninstall; explicitly dispose of data under the agreed retention process.

## Integration evidence to review before production

- Real SIEM parsing, indexing, dashboard queries and ingestion cost.
- Managed TLS/key rotation, credential compromise and session recovery.
- Independent workflow labeling, PII recall/precision and task utility.
- Container build, admission policy, NetworkPolicy and pod restart/PVC recovery.
- Resource limits, backpressure and realistic concurrent load.
- Multi-host revocation and consistent current-policy enforcement.

## Local execution limitation

The provider compiled and its Go SDK create/read/update/delete callbacks passed
against the real local HTTPS/mTLS/HMAC gateway. Terraform CLI plugin negotiation
could not execute here: this host forbids AF_UNIX sockets, which the standard
Linux go-plugin transport requires. The CLI lifecycle test is explicitly skipped
with that reason. Run it on a normal Linux host before claiming Terraform CLI
compatibility; no private fork of the plugin transport is used.

The source-only GitHub draft omits the original publication ZIP and compiled
provider binary. Its installer prepares `published/` from the same checkout's existing,
manifest-verified original source; no original publication content is re-uploaded. The downloadable package retains the original ZIP.
