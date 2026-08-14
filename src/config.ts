/**
 * Serializable PromptWall configuration and direct-call defaults.
 * @module dsh-promptwall/config
 */

import z from '@deepseek-ai/schemastery'
import type { FindingCategory, Severity } from './scanner.ts'

/** Action applied to suspicious tool output. */
export type InjectionAction = 'monitor' | 'sanitize' | 'block'

/** Action applied when a likely credential enters a network-capable tool. */
export type EgressAction = 'off' | 'ask' | 'deny'

/** User-defined deterministic prompt-injection rule. */
export interface InjectionRuleConfig {
  /** Stable lower-kebab-case rule id. */
  id: string
  /** Finding category reported to users. */
  category: FindingCategory
  /** Finding severity and score weight. */
  severity: Severity
  /** JavaScript regular-expression source. */
  pattern: string
  /** Optional JavaScript regular-expression flags; global matching is automatic. */
  flags?: string
  /** Safe explanation that never includes matched content. */
  description: string
}

/** User-defined deterministic secret pattern. */
export interface SecretPatternConfig {
  /** Stable lower-kebab-case label used in redaction markers. */
  id: string
  /** JavaScript regular-expression source. */
  pattern: string
  /** Optional JavaScript regular-expression flags; global matching is automatic. */
  flags?: string
}

/** PromptWall deployment configuration. */
export interface Config {
  /** Whether the tool and policy listeners are registered. */
  enabled?: boolean
  /** Policy applied to suspicious tool output. */
  injectionAction?: InjectionAction
  /** Minimum score for a suspicious verdict. */
  suspiciousThreshold?: number
  /** Minimum score for a dangerous verdict. */
  dangerousThreshold?: number
  /** Maximum UTF-16 code units inspected per text value. */
  maxScanChars?: number
  /** Maximum nesting depth accepted in one canonical JSON tool result. */
  maxJsonDepth?: number
  /** Maximum number of JSON values inspected in one canonical tool result. */
  maxJsonNodes?: number
  /** Whether every tool output is inspected unless trusted explicitly. */
  inspectToolOutputs?: boolean
  /** Exact tool names whose outputs bypass automatic inspection. */
  trustedTools?: string[]
  /** Policy for likely credentials in egress-tool arguments. */
  egressAction?: EgressAction
  /** Case-insensitive regular expressions identifying network-capable tool names. */
  egressToolPatterns?: string[]
  /** Additional injection rules compiled at plugin load. */
  rules?: InjectionRuleConfig[]
  /** Additional credential patterns compiled at plugin load. */
  secretPatterns?: SecretPatternConfig[]
}

/** Fully resolved PromptWall configuration. */
export interface ResolvedConfig {
  enabled: boolean
  injectionAction: InjectionAction
  suspiciousThreshold: number
  dangerousThreshold: number
  maxScanChars: number
  maxJsonDepth: number
  maxJsonNodes: number
  inspectToolOutputs: boolean
  trustedTools: readonly string[]
  egressAction: EgressAction
  egressToolPatterns: readonly string[]
  rules: readonly InjectionRuleConfig[]
  secretPatterns: readonly SecretPatternConfig[]
}

const findingCategory = z.union([
  'instruction-override',
  'role-hijack',
  'secret-exfiltration',
  'system-prompt-theft',
  'tool-coercion',
  'persistence',
  'obfuscation',
])

const severity = z.union(['low', 'medium', 'high', 'critical'])

/** Loader-visible configuration schema and defaults. */
export const Config: z<Config> = z.object({
  enabled: z.boolean().default(true),
  injectionAction: z.union(['monitor', 'sanitize', 'block']).default('sanitize'),
  suspiciousThreshold: z.number().min(1).max(99).default(30),
  dangerousThreshold: z.number().min(2).max(100).default(70),
  maxScanChars: z.number().min(1024).max(2_000_000).default(250_000),
  maxJsonDepth: z.number().min(8).max(2_048).default(256),
  maxJsonNodes: z.number().min(100).max(1_000_000).default(100_000),
  inspectToolOutputs: z.boolean().default(true),
  trustedTools: z.array(z.string()).default(['promptwall_scan']),
  egressAction: z.union(['off', 'ask', 'deny']).default('ask'),
  egressToolPatterns: z.array(z.string()).default([
    'web', 'fetch', 'http', 'browser', 'mcp', 'upload', 'email', 'slack', 'discord', 'telegram',
  ]),
  rules: z.array(z.object({
    id: z.string(),
    category: findingCategory,
    severity,
    pattern: z.string(),
    flags: z.string().default('iu'),
    description: z.string(),
  })).default([]),
  secretPatterns: z.array(z.object({
    id: z.string(),
    pattern: z.string(),
    flags: z.string().default('u'),
  })).default([]),
})

function assertIntegerInRange(value: number, name: string, minimum: number, maximum: number): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer from ${minimum} through ${maximum}`)
  }
}

/** Resolve and cross-validate configuration for Loader and direct callers. */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  const suspiciousThreshold = config.suspiciousThreshold ?? 30
  const dangerousThreshold = config.dangerousThreshold ?? 70
  const maxScanChars = config.maxScanChars ?? 250_000
  const maxJsonDepth = config.maxJsonDepth ?? 256
  const maxJsonNodes = config.maxJsonNodes ?? 100_000
  assertIntegerInRange(suspiciousThreshold, 'suspiciousThreshold', 1, 99)
  assertIntegerInRange(dangerousThreshold, 'dangerousThreshold', 2, 100)
  assertIntegerInRange(maxScanChars, 'maxScanChars', 1024, 2_000_000)
  assertIntegerInRange(maxJsonDepth, 'maxJsonDepth', 8, 2_048)
  assertIntegerInRange(maxJsonNodes, 'maxJsonNodes', 100, 1_000_000)
  if (suspiciousThreshold >= dangerousThreshold) {
    throw new TypeError('suspiciousThreshold must be lower than dangerousThreshold')
  }
  return {
    enabled: config.enabled ?? true,
    injectionAction: config.injectionAction ?? 'sanitize',
    suspiciousThreshold,
    dangerousThreshold,
    maxScanChars,
    maxJsonDepth,
    maxJsonNodes,
    inspectToolOutputs: config.inspectToolOutputs ?? true,
    trustedTools: config.trustedTools ?? ['promptwall_scan'],
    egressAction: config.egressAction ?? 'ask',
    egressToolPatterns: config.egressToolPatterns ?? [
      'web', 'fetch', 'http', 'browser', 'mcp', 'upload', 'email', 'slack', 'discord', 'telegram',
    ],
    rules: config.rules ?? [],
    secretPatterns: config.secretPatterns ?? [],
  }
}
