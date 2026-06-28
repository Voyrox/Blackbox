Resume version

You could frame it like this:

Secure Air-Gapped Update Distribution System
Rust, SQLite, Ed25519, SBOM, TUF-style metadata, Policy Engine

Built a secure software-update pipeline for disconnected environments with signed update bundles, offline verification, rollback protection, version pinning, and tamper-evident audit logs. Implemented a Rust CLI for package creation, USB import, metadata validation, SBOM policy checks, staged rollout, and install-state tracking. Tested realistic attack scenarios including payload tampering, stale metadata replay, downgrade attempts, unsigned packages, vulnerable dependencies, and interrupted installs.