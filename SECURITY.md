# Security Policy

PromptWall handles adversarial text and likely credentials. Please do not place real secrets, private documents, or weaponized payloads in a public issue.

For a vulnerability report, contact the repository owner privately and include the affected version, a minimal synthetic reproduction, expected impact, and any suggested mitigation. Replace all credentials with unmistakably fake values.

Supported security fixes currently target the latest `0.1.x` release line. Pattern-matching false positives and false negatives are security-relevant product limitations, but a report should distinguish them from secret disclosure, policy bypass, lifecycle escape, or unsafe logging defects.

Starting with `0.1.2`, release tarballs include a SHA-256 checksum and GitHub build-provenance attestation. Verify a downloaded archive with `sha256sum -c` and `gh attestation verify dsh-promptwall-0.1.2.tgz --repo Chhlafiu4312/promptwall` before installing it in a sensitive environment.
