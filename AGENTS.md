# PromptWall Contributor Notes

This repository is the standalone PromptWall plugin for DeepSeek Harness.

- Preserve the function-plugin named exports: `name`, `inject`, `Config`, and `apply`; do not add a default export.
- Keep Loader metadata in `src/index.ts`, schema/defaults in `src/config.ts`, and host boundaries plus activation in `src/runtime.ts`.
- Keep all registrations scoped to the plugin fiber and test disposal.
- Never log or persist matched credential values or raw quarantined payloads.
- Do not weaken injection or egress policy defaults without tests and a threat-model update.
- Do not use recursive deletion commands; generated outputs may be overwritten in place.
- Keep host-provided runtime APIs as peer dependencies and resolve development imports from this repository's declared dependencies.
- Do not add source, configuration, documentation, project-reference, `link:`, or `file:` paths that leave this repository.
- Describe repository files with project-root paths such as `docs/dsh-plugin-contracts.md`; never use parent-directory navigation in documentation.
- Update `README.md`, configuration JSDoc, tests, and `cordis.patch.yml` together when behavior changes.
- Keep the repository-local `.agents/skills/dsh-plugin-*` workflow synchronized with template paths, commands, and package conventions.
- Run `pnpm run verify:self-contained`, `pnpm run typecheck`, `pnpm test`, `pnpm run build`, and `pnpm run prepare` before publishing changes.
