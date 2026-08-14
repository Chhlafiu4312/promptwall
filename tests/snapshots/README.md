# Snapshot Fixtures

`promptwall-dangerous.md` is the stable user- and model-visible CLI receipt owned by `tests/cli.spec.ts`.

Do not add snapshots for internal object shapes, unstable timestamps, credentials, absolute workstation paths, or output that can be asserted more clearly with focused values. After `pnpm run prepare`, run `pnpm run snapshots:update` and review the changed fixture semantically.
