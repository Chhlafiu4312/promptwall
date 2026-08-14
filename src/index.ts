/**
 * PromptWall function plugin for DeepSeek Harness.
 * @module dsh-promptwall
 */

/** Cordis plugin name; keep this stable after publishing. */
export const name = 'promptwall'

/** Services that must exist before the plugin is applied. */
export const inject = ['tools']

export { Config } from './config.ts'
export type { ResolvedConfig } from './config.ts'
export { apply } from './runtime.ts'
export type { PluginRuntime } from './runtime.ts'
export { scanText, quarantineText, createScanner } from './scanner.ts'
export type { FindingCategory, InjectionFinding, ScanOptions, ScanReport, Severity, Verdict } from './scanner.ts'
export { scanSecrets, redactSecrets, createSecretScanner } from './secrets.ts'
export type { SecretFinding, SecretReport } from './secrets.ts'
export { formatPromptWallReport } from './tool.ts'
export type { PromptWallToolResult } from './tool.ts'
