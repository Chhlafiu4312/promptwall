# Changelog

## 0.1.3 - 2026-08-15

- Resolved packed release archives to absolute paths before the Harness clean-profile smoke install.
- Recorded the failed-closed v0.1.2 release attempt; no v0.1.2 archive was published.

## 0.1.2 - 2026-08-15

- Pinned every GitHub Action to an immutable commit and added dependency review and CodeQL analysis.
- Added weekly Dependabot updates, ownership and contribution templates, and a code of conduct.
- Added a tag-to-version gate, clean-profile installation smoke test, SHA-256 checksum, and build provenance attestation to automated releases.

## 0.1.1 - 2026-08-14

- Replaced recursive canonical JSON inspection with an iterative traversal.
- Added configurable JSON depth and node limits that fail closed on oversized structures.
- Added safe handling and regression coverage for cyclic non-JSON tool results.

## 0.1.0

- Added multilingual local prompt-injection scanning and quarantine.
- Added high-confidence credential detection and redaction.
- Added DSH pre-execution egress approval and post-execution output policy hooks.
- Added the `promptwall_scan` tool, standalone CLI, public scanner API, and lifecycle tests.
- Kept the optional invariant companion out of the default bundle so stock Harness Web and Headless profiles activate without an `invariants` service.
