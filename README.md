# Air-Gapped Update Distribution System

A CLI tool for securely distributing software, firmware, and configuration bundles into air-gapped (offline) environments. Packages are cryptographically signed with ECDSA P-256, contain an SBOM, and carry expiry metadata. All import and install operations are logged to a tamper-evident SQLite audit chain.

## What it does

This is a **package management tool for air-gapped networks**, not a generic file verifier. It does not verify ISOs or arbitrary files directly.

### Workflow

```
[connected machine]             [air-gapped machine]
          |                             |
  build .agpkg bundle                   |
  sign it with private key              |
          |                             |
  copy .agpkg + .sig                    |
  to USB / optical disc                 |
          |--- physical transfer --->   |
                               import (verify signature,
                               verify hashes, check expiry)
                                        |
                               install (record in store,
                                block downgrades)
```

The `.agpkg` format is the only format it understands. To ship an ISO (or any file), place it inside the payload directory when creating the package — the tool verifies its hash as part of the bundle integrity check.

### What it verifies

| Check             | What it does                                      |
|-------------------|----------------------------------------------------|
| Signature         | ECDSA P-256 signature of the entire `.agpkg` file |
| Payload hash      | SHA-256 of every file in the payload directory     |
| SBOM hash         | SHA-256 of the embedded SPDX SBOM                  |
| Metadata expiry   | Rejects packages past their `expires_at` date      |
| Rollback          | Blocks installation of versions older than current |

## Build

```
make
```

Requires: CMake, Ninja, libarchive, OpenSSL 1.1+, SQLite3.

## Commands

### Generate signing keys

```
airgapctl keygen --out keys
```

Output: `keys/release.key` (private) and `keys/release.key.pub` (public).

### Create a package

```
airgapctl package create \
    --name ics-firmware-v2 \
    --version 2.3.1 \
    --payload payload/ \
    --sbom sbom.spdx.json \
    --out dist/ics-firmware-v2-2.3.1.agpkg
```

Bundles the payload directory and SBOM into a gzipped tar archive with a JSON manifest.

### Sign a package

```
airgapctl package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
```

Creates `dist/ics-firmware-v2-2.3.1.agpkg.sig`.

### Import (verify) a package

```
airgapctl import dist/ics-firmware-v2-2.3.1.agpkg --trusted-key keys/release.key.pub
```

Verifies signature, payload hash, SBOM hash, expiry, and records the bundle in the local store. Each check is shown as a colored row in a results table (`✓ valid` / `✗ INVALID`).

### Install a package

```
airgapctl install ics-firmware-v2 --version 2.3.1
```

Marks the previously imported bundle as installed. Blocks downgrades.

### Show status

```
airgapctl status
```

Lists installed packages and imported bundles.

### Verify audit chain

```
airgapctl audit verify-chain
```

Cryptographically verifies every audit event links to the previous one, detecting tampering.

## Quick start

```sh
make run
```

Builds the tool and runs a full workflow: keygen → create → sign → import → install → status.

## Example walkthrough

```
$ airgapctl keygen --out keys
Generated key pair:
  Private: keys/release.key
  Public:  keys/release.key.pub

$ airgapctl package create \
    --name ics-firmware-v2 --version 2.3.1 \
    --payload test_payload --sbom test_sbom.json \
    --out dist/ics-firmware-v2-2.3.1.agpkg
Package created: dist/ics-firmware-v2-2.3.1.agpkg
  Package:      ics-firmware-v2 2.3.1
  Payload hash: sha256:faf12635aa995b88c0d2926f67b9e03a3cda214a488b5a5dd499945d982a4b9f
  SBOM hash:    sha256:bc161c2363449531fd6c3232e43b13af573f61c07b758882031f7cb024a57a90

$ airgapctl package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
Signature: dist/ics-firmware-v2-2.3.1.agpkg.sig

$ airgapctl import dist/ics-firmware-v2-2.3.1.agpkg --trusted-key keys/release.key.pub

  Signature    ✓ valid
  Bundle       ics-firmware-v2 2.3.1
  Payload hash ✓ valid
  SBOM         ✓ present
  SBOM hash    ✓ valid
  Expiry       ✓ valid
  Rollback     ✓ passed

  ✓ Status: imported and pending approval

$ airgapctl install ics-firmware-v2 --version 2.3.1
Installed: ics-firmware-v2 2.3.1

$ airgapctl status
Installed packages:
  ics-firmware-v2 2.3.1 (installed 2026-06-28 04:43:00)

Imported bundles:
  ics-firmware-v2 2.3.1 [imported] (imported 2026-06-28 04:43:00)

$ airgapctl audit verify-chain
Audit chain   ✓ valid
Events        4
```

## Package format

A `.agpkg` file is a gzipped tar archive containing:

```
payload/                  # application files (any content)
  ...
metadata/
  manifest.json           # package metadata (JSON)
  sbom.spdx.json          # SPDX Software Bill of Materials
```

### Manifest fields

| Field                 | Description                                |
|------------------------|--------------------------------------------|
| `package_name`         | Name of the package                        |
| `version`              | SemVer version string                      |
| `build_id`             | ISO 8601 timestamp of build time           |
| `target_os`            | Target operating system (default: linux)   |
| `target_arch`          | Target architecture (default: x86_64)      |
| `payload_hash`         | `sha256:` prefixed hash of payload tree    |
| `sbom_hash`            | `sha256:` prefixed hash of the SBOM        |
| `minimum_allowed_version` | Minimum installable version (default: 0.0.0) |
| `requires_reboot`      | Whether a reboot is needed after install   |
| `dependencies`         | List of `{ name, version }` pairs          |
| `created_by`           | Tool that created the package              |
| `expires_at`           | ISO 8601 expiry timestamp (default: +90d)  |

Signatures are stored alongside as `<package>.agpkg.sig` (raw ECDSA P-256 signature).
