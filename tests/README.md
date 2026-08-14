# Test Layout

`tests/plugin.spec.ts` owns the baseline Loader shape, configuration behavior, activation, invariant registration, and disposal evidence. `tests/harness.ts` provides the shared real-Cordis mount with an observable fake host boundary.

Extend test support only when the plugin requires it:

- extend `tests/harness.ts` when several suites need the same deterministic production composition;
- add `tests/<feature>.spec.ts` for focused feature behavior;
- add fixtures under `tests/snapshots/` for stable user-, model-, CLI-, terminal-, editor-, or browser-visible expected output.

A harness should mount production services and expose observable state rather than duplicate the implementation. `tests/cli.spec.ts` owns `tests/snapshots/promptwall-dangerous.md`. After `pnpm run prepare`, refresh it with `pnpm run snapshots:update`, then review the wording and ensure no secret value entered the fixture. Tests remain typechecked by `tsconfig.vitest.json`.
