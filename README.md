1. Architecture

You want three main components:

Connected side / staging network
        |
        | 1. Build update bundle
        | 2. Sign package + metadata
        | 3. Export to USB / ISO / tarball
        v
Transfer media
        |
        v
Air-gapped environment
        |
        | 4. Import bundle
        | 5. Verify signatures, SBOM, policy, version rules
        | 6. Stage rollout
        | 7. Install or reject
        v
Offline target machines

You can implement this with:

airgapctl build
airgapctl sign
airgapctl export
airgapctl import
airgapctl verify
airgapctl approve
airgapctl install
airgapctl rollback
airgapctl audit

Use Rust for the CLI and verification engine.

2. What an update package looks like

Each update should be a self-contained bundle:

update-bundle/
├── payload/
│   ├── app-linux-amd64.tar.zst
│   ├── config-migrations/
│   └── install.sh
├── metadata/
│   ├── manifest.json
│   ├── sbom.spdx.json
│   ├── vulnerabilities.json
│   ├── policy.json
│   └── tuf-metadata.json
├── signatures/
│   ├── manifest.sig
│   ├── sbom.sig
│   └── payload.sig
└── bundle.toml

The manifest is the most important file.

Example:

{
  "package_name": "sensor-agent",
  "version": "1.4.2",
  "build_id": "2026-06-28T03:22:11Z",
  "target_os": "linux",
  "target_arch": "x86_64",
  "payload_hash": "sha256:...",
  "sbom_hash": "sha256:...",
  "minimum_allowed_version": "1.3.0",
  "requires_reboot": false,
  "dependencies": [
    {
      "name": "openssl",
      "version": "3.3.1"
    }
  ],
  "created_by": "release-pipeline",
  "expires_at": "2026-09-28T00:00:00Z"
}

The offline system should never trust filenames. It should trust only hashes and signed metadata.

3. Signing model

For a strong resume project, implement role-based signing, inspired by TUF:

root key         -> trusts release/signing keys
targets key      -> signs package metadata
snapshot key     -> signs repository state
timestamp key    -> signs freshness/expiry metadata
approver key     -> signs offline approval decision

You do not need to fully implement TUF at first. You can build a TUF-style metadata system.

Example trust chain:

root.json
  └── targets.json
        └── manifest.json
              └── payload hash

The offline environment has the root public key pinned.

That means even if someone inserts a malicious USB, the import tool rejects it unless the bundle chains back to the trusted offline root.

4. Offline verification flow

When someone imports a USB:

airgapctl import /media/usb/update-bundle

The tool should perform checks in this order:

1. Read bundle metadata
2. Verify root metadata is trusted
3. Verify package signatures
4. Verify payload hash
5. Verify SBOM hash
6. Check metadata expiry
7. Check version is allowed
8. Check package is not a rollback/downgrade
9. Check policy gates
10. Store bundle in local offline repository
11. Write audit log

Example output:

Bundle: sensor-agent 1.4.2
Signature: valid
Payload hash: valid
SBOM: valid
Metadata expiry: valid
Rollback check: passed
Policy: passed
Status: imported and pending approval

Rejected example:

Bundle rejected

Reason:
- Version 1.2.0 is older than currently installed version 1.4.1
- Manifest signature is valid, but rollback policy blocks downgrade
- Audit event written: AUDIT-2026-000183

That looks very real.

5. Rollback protection

This is one of the most important parts.

Keep a local SQLite database:

CREATE TABLE installed_versions (
    package_name TEXT PRIMARY KEY,
    current_version TEXT NOT NULL,
    previous_version TEXT,
    installed_at TEXT NOT NULL,
    manifest_hash TEXT NOT NULL
);

CREATE TABLE blocked_versions (
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (package_name, version)
);

CREATE TABLE imported_bundles (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

Rollback logic:

Reject install if:
- version < current installed version
- version is in blocked_versions
- manifest hash has already been rejected
- metadata has expired
- bundle generation number is lower than the last accepted generation

Use semantic versioning for normal packages:

semver::Version

But also add a monotonic release counter:

{
  "version": "1.4.2",
  "release_counter": 1042
}

That prevents someone from republishing an old version with weird version formatting.

6. Version pinning

Version pinning means offline admins can say:

This environment is allowed to install only:
sensor-agent 1.4.x
kernel-module 5.10.0-92
database-agent exactly 2.3.7

Example policy.toml:

[packages.sensor-agent]
allowed = ">=1.4.0, <1.5.0"
deny_downgrade = true
require_sbom = true
require_approval = true

[packages.database-agent]
allowed = "=2.3.7"
deny_downgrade = true
require_sbom = true
require_no_critical_vulns = true

Install command:

airgapctl install sensor-agent --version 1.4.2

If it violates the policy:

Install blocked:
sensor-agent 1.5.0 is outside allowed range >=1.4.0, <1.5.0

This is a good “defence enterprise” feature because offline environments often move slowly and need controlled update baselines.

7. SBOM verification

Each bundle should include an SBOM:

sbom.spdx.json

or

sbom.cyclonedx.json

The offline verifier checks:

- SBOM exists
- SBOM hash matches manifest
- SBOM signature is valid
- SBOM package list matches expected package
- vulnerability policy passes

For the project, you can simulate vulnerability gating with an offline vulnerability database:

offline-vuln-db.json

Example:

{
  "openssl": {
    "3.0.0": {
      "cves": ["CVE-2022-0778"],
      "severity": "high"
    }
  },
  "log4j": {
    "2.14.1": {
      "cves": ["CVE-2021-44228"],
      "severity": "critical"
    }
  }
}

Policy:

[vulnerability_policy]
block_critical = true
block_high = false
allowlist = [
  "CVE-2022-1234"
]

Then your verifier can say:

SBOM policy failed:
- log4j 2.14.1 has critical vulnerability CVE-2021-44228
- install blocked by policy

That’s a strong resume bullet.

8. Audit logs

Do not just print logs. Store structured audit events.

SQLite table:

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    package_name TEXT,
    version TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    metadata_hash TEXT,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL
);

The important feature is hash-chained audit logs.

Each event contains the hash of the previous event:

event_hash = sha256(event_data + previous_event_hash)

This makes tampering detectable.

Example audit command:

airgapctl audit verify-chain

Output:

Audit chain valid
Events checked: 184
First event: 2026-06-01T09:10:00Z
Latest event: 2026-06-28T14:33:22Z

This is very defence-relevant.

9. Staged rollout

Model offline machines as groups:

ring-0: test machine
ring-1: admin workstations
ring-2: operational systems
ring-3: all remaining systems

SQLite:

CREATE TABLE machines (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ring TEXT NOT NULL,
    current_version TEXT,
    last_seen TEXT
);

CREATE TABLE rollout_plans (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE rollout_targets (
    rollout_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    status TEXT NOT NULL,
    installed_at TEXT,
    error TEXT,
    PRIMARY KEY (rollout_id, machine_id)
);

Commands:

airgapctl rollout create sensor-agent 1.4.2 --ring ring-0
airgapctl rollout promote sensor-agent 1.4.2 --to ring-1
airgapctl rollout status

Example status:

Rollout: sensor-agent 1.4.2

ring-0:
  completed: 3/3
  failed: 0

ring-1:
  completed: 8/10
  failed: 1
  pending: 1

ring-2:
  not started


MVP build order

Build it in this order.

Phase 1: Package format

Create:

airgapctl package create \
  --name sensor-agent \
  --version 1.0.0 \
  --payload ./payload \
  --sbom ./sbom.spdx.json \
  --out ./dist/sensor-agent-1.0.0.agpkg

The .agpkg can just be a compressed tarball.

Output:

sensor-agent-1.0.0.agpkg
Phase 2: Signing
airgapctl keygen --out keys/
airgapctl package sign ./dist/sensor-agent-1.0.0.agpkg --key keys/release.key

This creates:

sensor-agent-1.0.0.agpkg
sensor-agent-1.0.0.agpkg.sig
Phase 3: Offline import and verify
airgapctl import ./sensor-agent-1.0.0.agpkg

Checks:

- signature valid
- hash valid
- metadata valid
- SBOM exists
- version is not blocked
Phase 4: Install state
airgapctl install sensor-agent --version 1.0.0
airgapctl status

Store installed state in SQLite.

Phase 5: Rollback protection

Try importing:

sensor-agent 0.9.0

Expected:

Rejected: downgrade detected
Phase 6: SBOM policy gate

Add fake vulnerable dependency:

{
  "name": "log4j",
  "version": "2.14.1"
}

Expected:

Rejected: critical vulnerability blocked by policy
Phase 7: Audit log

Every action writes an event:

PACKAGE_IMPORTED
PACKAGE_REJECTED
PACKAGE_APPROVED
PACKAGE_INSTALLED
ROLLBACK_BLOCKED
POLICY_FAILED
AUDIT_CHAIN_VERIFIED
12. Nice repo structure
airgap-update/
├── crates/
│   ├── airgapctl/
│   │   └── src/main.rs
│   ├── package/
│   │   └── src/lib.rs
│   ├── crypto/
│   │   └── src/lib.rs
│   ├── policy/
│   │   └── src/lib.rs
│   ├── sbom/
│   │   └── src/lib.rs
│   ├── audit/
│   │   └── src/lib.rs
│   └── store/
│       └── src/lib.rs
├── examples/
│   ├── valid-update/
│   ├── tampered-update/
│   ├── rollback-update/
│   └── vulnerable-sbom/
├── docs/
│   ├── threat-model.md
│   ├── package-format.md
│   ├── verification-flow.md
│   └── demo-script.md
└── README.md


Threat model to include in the README

This is what makes it defence-grade.

Your project should explicitly defend against:

1. Malicious USB containing unsigned package
2. Valid old package used for downgrade attack
3. Tampered payload after signing
4. Tampered SBOM
5. Expired metadata replayed into offline environment
6. Package with vulnerable dependency
7. Interrupted install
8. Unauthorized operator approval
9. Audit log modification

And explicitly not defend against:

1. Fully compromised offline root administrator
2. Physical hardware implant
3. Compromised trusted signing key
4. Malicious code that was validly signed by the release authority

That honesty actually makes the project look more professional.