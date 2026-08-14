/** Deterministic multilingual prompt-injection scanner. */

import type { InjectionRuleConfig } from './config.ts'

/** Finding severity ordered from informational to immediate threat. */
export type Severity = 'low' | 'medium' | 'high' | 'critical'

/** Behavioral technique associated with a finding. */
export type FindingCategory =
  | 'instruction-override'
  | 'role-hijack'
  | 'secret-exfiltration'
  | 'system-prompt-theft'
  | 'tool-coercion'
  | 'persistence'
  | 'obfuscation'

/** Overall prompt-injection assessment. */
export type Verdict = 'clean' | 'suspicious' | 'dangerous'

/** One matched rule without raw secret-bearing payload retention. */
export interface InjectionFinding {
  readonly ruleId: string
  readonly category: FindingCategory
  readonly severity: Severity
  readonly description: string
  readonly start: number
  readonly end: number
  readonly excerpt: string
}

/** Complete deterministic scan result. */
export interface ScanReport {
  readonly version: 1
  readonly verdict: Verdict
  readonly score: number
  readonly scannedChars: number
  readonly totalChars: number
  readonly truncated: boolean
  readonly findings: readonly InjectionFinding[]
}

/** Scanner configuration independent of the DSH runtime. */
export interface ScanOptions {
  readonly suspiciousThreshold?: number
  readonly dangerousThreshold?: number
  readonly maxScanChars?: number
  readonly rules?: readonly InjectionRuleConfig[]
}

/** Compiled prompt-injection rule used by a reusable scanner. */
export interface CompiledRule {
  readonly id: string
  readonly category: FindingCategory
  readonly severity: Severity
  readonly description: string
  readonly expression: RegExp
}

const SEVERITY_SCORE: Readonly<Record<Severity, number>> = {
  low: 15,
  medium: 30,
  high: 45,
  critical: 70,
}

const BUILTIN_RULE_SPECS: readonly InjectionRuleConfig[] = [
  {
    id: 'override-previous-instructions',
    category: 'instruction-override',
    severity: 'critical',
    pattern: String.raw`(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your)\s+)?(?:previous|prior|earlier|system|developer|safety)\s+(?:instructions?|rules?|messages?|constraints?)`,
    flags: 'iu',
    description: 'Attempts to replace earlier instructions or safety constraints.',
  },
  {
    id: 'override-previous-instructions-zh',
    category: 'instruction-override',
    severity: 'critical',
    pattern: String.raw`(?:忽略|无视|忘记|覆盖|绕过).{0,16}(?:之前|先前|以上|系统|开发者|安全).{0,12}(?:指令|规则|要求|限制|消息)`,
    flags: 'iu',
    description: 'Attempts to replace earlier instructions or safety constraints in Chinese.',
  },
  {
    id: 'fake-authority',
    category: 'role-hijack',
    severity: 'high',
    pattern: String.raw`(?:this\s+is|treat\s+this\s+as)\s+(?:a\s+)?(?:system|developer|administrator|highest[- ]priority)\s+(?:message|instruction|directive)|\[(?:system|developer|admin)\]|<\/?(?:system|developer)>`,
    flags: 'iu',
    description: 'Claims a higher-priority role inside untrusted content.',
  },
  {
    id: 'fake-authority-zh',
    category: 'role-hijack',
    severity: 'high',
    pattern: String.raw`(?:这是|视为|当作).{0,8}(?:系统|开发者|管理员|最高优先级).{0,8}(?:消息|指令|命令)`,
    flags: 'iu',
    description: 'Claims a higher-priority role inside untrusted Chinese content.',
  },
  {
    id: 'system-prompt-theft',
    category: 'system-prompt-theft',
    severity: 'high',
    pattern: String.raw`(?:reveal|show|print|repeat|dump|return|expose).{0,32}(?:system|developer|hidden|initial)\s+(?:prompt|message|instructions?)`,
    flags: 'iu',
    description: 'Requests disclosure of hidden system or developer instructions.',
  },
  {
    id: 'system-prompt-theft-zh',
    category: 'system-prompt-theft',
    severity: 'high',
    pattern: String.raw`(?:显示|输出|打印|泄露|重复|返回).{0,24}(?:系统|开发者|隐藏|初始).{0,8}(?:提示词|提示|指令|消息)`,
    flags: 'iu',
    description: 'Requests disclosure of hidden system or developer instructions in Chinese.',
  },
  {
    id: 'credential-exfiltration',
    category: 'secret-exfiltration',
    severity: 'critical',
    pattern: String.raw`(?:send|post|upload|exfiltrat(?:e|ion)|transmit|forward).{0,48}(?:api[-_ ]?key|token|password|credential|secret|\.env|environment\s+variables?)`,
    flags: 'iu',
    description: 'Requests transmission of credentials or environment secrets.',
  },
  {
    id: 'credential-exfiltration-zh',
    category: 'secret-exfiltration',
    severity: 'critical',
    pattern: String.raw`(?:发送|上传|提交|转发|泄露).{0,36}(?:密钥|令牌|密码|凭据|秘密|环境变量|\.env)`,
    flags: 'iu',
    description: 'Requests transmission of credentials or environment secrets in Chinese.',
  },
  {
    id: 'coerce-shell-or-tool',
    category: 'tool-coercion',
    severity: 'medium',
    pattern: String.raw`(?:run|execute|invoke|call)\s+(?:(?:the|this|following)\s+)?(?:shell|terminal|bash|command|tool)|(?:curl|wget)\s+[^\n|]{1,160}\|\s*(?:ba|z|fi)?sh`,
    flags: 'iu',
    description: 'Attempts to make the agent execute a command embedded in content.',
  },
  {
    id: 'coerce-shell-or-tool-zh',
    category: 'tool-coercion',
    severity: 'medium',
    pattern: String.raw`(?:运行|执行|调用).{0,12}(?:命令|工具|终端|脚本|bash|shell)`,
    flags: 'iu',
    description: 'Attempts to make the agent execute a command embedded in Chinese content.',
  },
  {
    id: 'persistence-instructions',
    category: 'persistence',
    severity: 'medium',
    pattern: String.raw`(?:write|append|save|store|persist).{0,40}(?:instruction|prompt|payload).{0,40}(?:memory|skill|agents?\.md|claude\.md|system\s+prompt)`,
    flags: 'iu',
    description: 'Attempts to persist untrusted instructions into future agent context.',
  },
  {
    id: 'unicode-control-characters',
    category: 'obfuscation',
    severity: 'medium',
    pattern: String.raw`[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]`,
    flags: 'u',
    description: 'Contains invisible or bidirectional control characters.',
  },
  {
    id: 'encoded-instruction-payload',
    category: 'obfuscation',
    severity: 'medium',
    pattern: String.raw`(?:decode|base64|rot13|deobfuscate).{0,32}[A-Za-z0-9+/]{80,}={0,2}`,
    flags: 'iu',
    description: 'Pairs a decoding instruction with a long encoded payload.',
  },
]

function canonicalizeFixedWidth(input: string): string {
  return input
    .replace(new RegExp('[\\uFF01-\\uFF5E]', 'gu'), character => String.fromCharCode(character.charCodeAt(0) - 0xFEE0))
    .replace(new RegExp('\\u3000', 'gu'), ' ')
}

function regexFlags(flags: string | undefined): string {
  const requested = flags ?? 'iu'
  if (new RegExp('[^dimsuvy]', 'u').test(requested)) throw new TypeError(`unsupported regular-expression flags ${JSON.stringify(requested)}`)
  return [...new Set(requested.replaceAll('y', '') + 'g')].join('')
}

function assertRuleId(id: string): void {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(id)) {
    throw new TypeError(`PromptWall rule id must be lower-kebab-case, got ${JSON.stringify(id)}`)
  }
}

function compileRule(spec: InjectionRuleConfig): CompiledRule {
  assertRuleId(spec.id)
  if (spec.description.trim().length === 0) throw new TypeError(`PromptWall rule ${spec.id} requires a description`)
  return {
    id: spec.id,
    category: spec.category,
    severity: spec.severity,
    description: spec.description,
    expression: new RegExp(spec.pattern, regexFlags(spec.flags)),
  }
}

/** Compile built-in and custom rules, rejecting duplicate ids at load time. */
export function compileRules(custom: readonly InjectionRuleConfig[] = []): readonly CompiledRule[] {
  const rules = [...BUILTIN_RULE_SPECS, ...custom].map(compileRule)
  const seen = new Set<string>()
  for (const rule of rules) {
    if (seen.has(rule.id)) throw new TypeError(`duplicate PromptWall rule id ${JSON.stringify(rule.id)}`)
    seen.add(rule.id)
  }
  return rules
}

function safeExcerpt(input: string, start: number, end: number): string {
  const before = Math.max(0, start - 32)
  const after = Math.min(input.length, end + 32)
  const excerpt = input.slice(before, after).replace(/\s+/gu, ' ').trim()
  return excerpt.length <= 120 ? excerpt : `${excerpt.slice(0, 117)}...`
}

function scanWindow(
  original: string,
  offset: number,
  length: number,
  rules: readonly CompiledRule[],
): InjectionFinding[] {
  const raw = original.slice(offset, offset + length)
  const canonical = canonicalizeFixedWidth(raw)
  const findings: InjectionFinding[] = []
  for (const rule of rules) {
    rule.expression.lastIndex = 0
    let perRule = 0
    for (const match of canonical.matchAll(rule.expression)) {
      if (match.index === undefined || match[0].length === 0) continue
      const start = offset + match.index
      const end = start + match[0].length
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        start,
        end,
        excerpt: safeExcerpt(original, start, end),
      })
      perRule += 1
      if (perRule === 3) break
    }
  }
  return findings
}

function deduplicateFindings(findings: readonly InjectionFinding[]): InjectionFinding[] {
  const unique = new Map<string, InjectionFinding>()
  for (const finding of findings) unique.set(`${finding.ruleId}:${finding.start}:${finding.end}`, finding)
  return [...unique.values()].sort((left, right) => left.start - right.start || right.end - left.end || left.ruleId.localeCompare(right.ruleId))
}

function scoreFindings(findings: readonly InjectionFinding[]): number {
  const firstByRule = new Map<string, Severity>()
  const categories = new Set<FindingCategory>()
  for (const finding of findings) {
    if (!firstByRule.has(finding.ruleId)) firstByRule.set(finding.ruleId, finding.severity)
    categories.add(finding.category)
  }
  let score = 0
  for (const ruleSeverity of firstByRule.values()) score += SEVERITY_SCORE[ruleSeverity]
  score += Math.max(0, categories.size - 1) * 5
  return Math.min(100, score)
}

/** Scan one text value against an already compiled rule set. */
function scanWithRules(input: string, options: ScanOptions, rules: readonly CompiledRule[]): ScanReport {
  const suspiciousThreshold = options.suspiciousThreshold ?? 30
  const dangerousThreshold = options.dangerousThreshold ?? 70
  const maxScanChars = options.maxScanChars ?? 250_000
  const truncated = input.length > maxScanChars
  const findings = truncated
    ? deduplicateFindings([
        ...scanWindow(input, 0, Math.floor(maxScanChars / 2), rules),
        ...scanWindow(input, input.length - Math.ceil(maxScanChars / 2), Math.ceil(maxScanChars / 2), rules),
      ])
    : deduplicateFindings(scanWindow(input, 0, input.length, rules))
  const score = truncated ? 100 : scoreFindings(findings)
  const hasCritical = findings.some(finding => finding.severity === 'critical')
  const verdict: Verdict = truncated || hasCritical || score >= dangerousThreshold
    ? 'dangerous'
    : score >= suspiciousThreshold
      ? 'suspicious'
      : 'clean'
  return {
    version: 1,
    verdict,
    score,
    scannedChars: Math.min(input.length, maxScanChars),
    totalChars: input.length,
    truncated,
    findings,
  }
}

/** Build a scanner that compiles its rule set exactly once. */
export function createScanner(options: ScanOptions = {}): (input: string) => ScanReport {
  const rules = compileRules(options.rules)
  return input => scanWithRules(input, options, rules)
}

/** Scan text locally without executing or decoding its contents. */
export function scanText(input: string, options: ScanOptions = {}): ScanReport {
  return createScanner(options)(input)
}

/** Replace matched injection spans while retaining surrounding source data. */
export function quarantineText(input: string, report: ScanReport): string {
  if (report.findings.length === 0) return input
  const ranges: Array<{ start: number; end: number; ids: Set<string> }> = []
  for (const finding of report.findings) {
    const previous = ranges.at(-1)
    if (previous !== undefined && finding.start <= previous.end) {
      previous.end = Math.max(previous.end, finding.end)
      previous.ids.add(finding.ruleId)
    } else {
      ranges.push({ start: finding.start, end: finding.end, ids: new Set([finding.ruleId]) })
    }
  }
  let output = ''
  let cursor = 0
  for (const range of ranges) {
    output += input.slice(cursor, range.start)
    output += `[PROMPTWALL_QUARANTINED:${[...range.ids].sort().join(',')}]`
    cursor = range.end
  }
  return output + input.slice(cursor)
}
