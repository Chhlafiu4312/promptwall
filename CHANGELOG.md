# Changelog

## 0.1.6 - 2026-08-15

- Inspected both canonical JSON values and their independent rendered content projections for successful tool results.
- Applied output policy to downstream content replacements before they become model-visible.
- Preserved safe sanitization by replacing content when only rendering changes and replacing values through the trusted pure renderer when canonical data changes.
- Correctly treated an explicit downstream `null` as a value replacement instead of falling back to discarded output.
- Added regression coverage for dangerous and suspicious rendered output, downstream replacements, and null values.

## 0.1.5 - 2026-08-15

- Inspected every string-bearing field in merge-extensible model-visible content blocks, including reasoning and nested tool-result blocks.
- Inspected tool-provided and downstream `additionalContexts` before they can enter the next model request.
- Failed closed when an unsafe tool-provided context requires rewriting that the post-execution contract cannot safely perform.
- Added regression coverage for non-text content blocks and clean, suspicious, and dangerous additional contexts.

## 0.1.4 - 2026-08-15

- Bounded credential scanning with the same per-string resource ceiling used by prompt-injection inspection.
- Failed closed when egress arguments exceed the credential scan limit or cannot be serialized instead of treating an incomplete scan as clean.
- Capped adversarial match counts and replaced partially redacted output with a safe scan-limit marker.
- Added regression coverage for oversized egress arguments, bounded scans, and high-match-count inputs.

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
