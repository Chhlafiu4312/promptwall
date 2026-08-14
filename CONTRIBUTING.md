# Contributing

Contributions are welcome, especially small reproducible bypass cases, multilingual rules, false-positive reductions, and DSH compatibility fixes.

1. Open an issue describing the behavior and a synthetic input.
2. Keep rules deterministic and give every new rule a stable lower-kebab-case id.
3. Add focused tests that cover the malicious case and a nearby benign case.
4. Never commit live credentials or private prompt content.
5. Run the full local verification sequence documented in [README.md](README.md).

Changes to default thresholds, trusted tools, egress matching, or logging require an accompanying update to [docs/design.md](docs/design.md). Keep every Cordis registration owned by the plugin fiber so disposal removes it.
