# Changelog

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
