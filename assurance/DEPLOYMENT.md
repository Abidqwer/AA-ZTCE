# Implemented assurance integrations

The code paths now exist and run in the virtual range. Physical hardware security,
independent witness administration and multi-host deployment remain unvalidated.
Use `../VIRTUAL_RANGE.md` for the one-command executed environment.

## Components and configuration contract

`gateway.py` accepts optional `signing` and `assurance` objects in its existing private
configuration. Existing configurations retain their prior behavior, including
masking. Unknown provider types or assurance fields fail startup.

- `enterprise.keys.PKCS11Ed25519`: token-generated, sensitive/non-exportable Ed25519
  keys. Requires a reported hardware slot unless an explicit software-token test
  flag is set. A module's hardware flag is not vendor hardware attestation.
- `assurance.tpm.TPM`: P-256 audit signing via a persistent TPM handle; separate
  restricted signing key for PCR quotes. TPM2-tools, key auth files and selected
  persistent handles are required. No host Ed25519 private key is silently exported
  into a TPM, and no TPM Ed25519 capability is assumed.
- `assurance.witness.Witness`: mutual-TLS admission, per-node certificate fingerprints,
  pinned audit/attestation keys, durable sequential anchors, signed receipts,
  fresh quote challenges and approved PCR-snapshot fingerprints.
- `assurance.etcd.Revocations`: linearizable agent epochs, session restrictions,
  conditional per-operation authorization, idempotent fresh-auth commands and
  per-node write watermarks, using a real etcd service.

The `assurance` object contains `domain_id`, `node_id`, `tpm`, `witness`, `consensus`,
optional `consensus_control`, and `attest_every_operation` (default true).
The CLI builds these complete objects from actual device/certificate paths:

```bash
python assurance_cli.py --help
python assurance_cli.py provision-tpm --help
python assurance_cli.py keygen-hsm --help
python assurance_cli.py quote-tpm --help
python assurance_cli.py init-witness --help
python assurance_cli.py enroll-witness --help
python assurance_cli.py make-profile --help
python assurance_cli.py attach --help
python assurance_cli.py revoke --help
```

Provisioning refuses occupied handles, duplicate key labels and existing witness
identity files. TPM owner authentication can be supplied during provisioning and
is not copied into the gateway's runtime profile. The emulator-only transient
cleanup option must never be used for shared or physical devices. Ordinary physical
provisioning expects the kernel resource manager (`device:/dev/tpmrm0`).

## Enforcement guarantees and their scope

Admission requires fresh appraised attestation when the profile is enabled. The
quote's nonce binds domain/node, client certificate, registered gateway public-key
hash and request context. AK and PCR-reference enrollment are out-of-band trust
inputs; automatic manufacturer EK-chain enrollment is not implemented.

A strict protected operation re-attests by default and then commits an etcd
transaction comparing the current agent/session state before recording its ordered
authorization decision. This serializes the decision with revocation. It does not
create a distributed transaction with arbitrary external tools. In-flight decisions
that precede revocation may complete; plaintext cannot be recalled.

The journal commits locally, signs its next canonical head with the configured TPM
audit key and waits for an independently pinned witness receipt before a successful
response returns. Startup compares the external head to local history and refuses
rollback/forks. Lost acknowledgments can be retried without duplicate anchors.
A fully rewritten local chain is rejected against the witness's accepted head.

No TPM NVRAM journal or NV-counter anti-rollback protocol is claimed. The anchor is
TPM-signed and independently retained. The witness protects against alteration by
a compromised gateway only while its own keys, database and administration remain
trusted; independent retention and backup still require operational controls.

## Threat-model boundaries

Key non-exportability does not prevent an authorized compromised host invoking a
signer or supplying false events. PCR appraisal does not establish complete runtime
integrity. Witness/consensus roles, gateways and enrollment registries remain trusted
components under the stated crash-fault model. A compromised control writer can
change authority. Default enforcers have read-only revocation access and may write
only their own decision key; do not co-locate privileged control credentials in a
production enforcement process.

Do not translate `distributed.status=committed` into 'every node already actuated.'
A successful SOAR response covers the authoritative commit and local action; the
current interface does not collect per-node actuation acknowledgments. Network
partitions can reduce availability because uncertain authority fails closed.
