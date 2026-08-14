# PromptWall Design

## Objective

PromptWall prevents instructions embedded in untrusted tool output from silently changing an agent's behavior and prevents high-confidence credentials from leaving through network-capable tools.

## Plugin contract

- Package: `dsh-promptwall`
- Cordis id: `promptwall`
- Form: function plugin
- Roles: DSH tool, pre-execution policy consumer, post-execution policy consumer, bundle
- Required service: `tools`
- Target profiles: Web and Headless
- Distribution: local and Git installation first; npm publication remains a separate decision

## Security defaults

Detection runs locally. PromptWall does not call a model or a remote service. It never logs matched secret values. High-confidence prompt injection is quarantined, lower-confidence findings are annotated, and suspected egress of credentials requires approval rather than being silently allowed. Prompt and credential scans share a bounded input ceiling; incomplete credential inspection fails closed and never produces a partially redacted value that callers could mistake for safe output. Post-execution inspection traverses every string-bearing field in merge-extensible content blocks and both tool-provided and downstream additional contexts. Tool-provided contexts fail closed whenever they require rewriting because the Harness contract preserves rather than replaces them on acceptance.

## Invariant decision

The stock bundle does not install a runtime invariant. PromptWall owns no durable event sequence or mutable relation across tool calls; the host owns tool-result logging. The package still exports an optional companion for custom profiles that explicitly mount Harness's `invariants` service.

## Evidence

Unit tests cover multilingual detection, normalization, overlapping findings, sanitization, bounded secret detection, oversized egress arguments, merge-extensible content blocks, additional contexts, and policy decisions. Cordis tests cover registration and disposal. Stable CLI output has snapshots. A package check covers self-containment, types, tests, build, and archive contents.
