/** High-confidence credential detection and redaction. */

import type { SecretPatternConfig } from './config.ts'

/** One secret match that intentionally omits the matched value. */
export interface SecretFinding {
  readonly id: string
  readonly start: number
  readonly end: number
}

/** Secret scan result suitable for logs and policy decisions. */
export interface SecretReport {
  readonly count: number
  readonly labels: readonly string[]
  readonly findings: readonly SecretFinding[]
  /** Number of UTF-16 code units inspected. */
  readonly scannedChars: number
  /** Original input size in UTF-16 code units. */
  readonly totalChars: number
  /** Whether an input or finding limit prevented a complete scan. */
  readonly truncated: boolean
}

/** Resource limits for one credential scan. */
export interface SecretScanOptions {
  readonly maxScanChars?: number
}

/** Compiled secret pattern used by a reusable scanner. */
export interface CompiledSecretPattern {
  readonly id: string
  readonly expression: RegExp
}

const BUILTIN_SECRET_PATTERNS: readonly SecretPatternConfig[] = [
  { id: 'private-key', pattern: String.raw`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`, flags: 'u' },
  { id: 'aws-access-key', pattern: String.raw`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, flags: 'u' },
  { id: 'github-token', pattern: String.raw`\bgh[pousr]_[A-Za-z0-9_]{20,255}\b`, flags: 'u' },
  { id: 'slack-token', pattern: String.raw`\bxox[baprs]-[A-Za-z0-9-]{10,200}\b`, flags: 'u' },
  { id: 'stripe-live-key', pattern: String.raw`\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b`, flags: 'u' },
  { id: 'generic-api-key', pattern: String.raw`\bsk-[A-Za-z0-9_-]{20,}\b`, flags: 'u' },
  { id: 'bearer-token', pattern: String.raw`\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b`, flags: 'iu' },
  { id: 'jwt', pattern: String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, flags: 'u' },
  {
    id: 'credential-assignment',
    pattern: String.raw`\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\s*[:=]\s*["']?[^\s,"'}]{12,}`,
    flags: 'iu',
  },
]

const DEFAULT_MAX_SCAN_CHARS = 250_000
const MAX_FINDINGS_PER_PATTERN_AND_WINDOW = 100
const SECRET_SCAN_LIMIT_MARKER = '<redacted:scan-limit>'

function flags(input: string | undefined): string {
  const requested = input ?? 'u'
  if (new RegExp('[^dimsuvy]', 'u').test(requested)) throw new TypeError(`unsupported regular-expression flags ${JSON.stringify(requested)}`)
  return [...new Set(requested.replaceAll('y', '') + 'g')].join('')
}

function compilePattern(spec: SecretPatternConfig): CompiledSecretPattern {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(spec.id)) {
    throw new TypeError(`PromptWall secret id must be lower-kebab-case, got ${JSON.stringify(spec.id)}`)
  }
  return { id: spec.id, expression: new RegExp(spec.pattern, flags(spec.flags)) }
}

/** Compile built-in and custom patterns, rejecting duplicate labels. */
export function compileSecretPatterns(custom: readonly SecretPatternConfig[] = []): readonly CompiledSecretPattern[] {
  const patterns = [...BUILTIN_SECRET_PATTERNS, ...custom].map(compilePattern)
  const seen = new Set<string>()
  for (const pattern of patterns) {
    if (seen.has(pattern.id)) throw new TypeError(`duplicate PromptWall secret id ${JSON.stringify(pattern.id)}`)
    seen.add(pattern.id)
  }
  return patterns
}

function scanWindow(
  input: string,
  offset: number,
  length: number,
  patterns: readonly CompiledSecretPattern[],
): { readonly findings: SecretFinding[]; readonly limited: boolean } {
  const window = input.slice(offset, offset + length)
  const findings: SecretFinding[] = []
  let limited = false
  for (const pattern of patterns) {
    pattern.expression.lastIndex = 0
    let perPattern = 0
    for (const match of window.matchAll(pattern.expression)) {
      if (match.index === undefined || match[0].length === 0) continue
      perPattern += 1
      if (perPattern > MAX_FINDINGS_PER_PATTERN_AND_WINDOW) {
        limited = true
        break
      }
      findings.push({ id: pattern.id, start: offset + match.index, end: offset + match.index + match[0].length })
    }
  }
  return { findings, limited }
}

/** Scan one value against an already compiled secret-pattern set. */
function scanWithPatterns(input: string, patterns: readonly CompiledSecretPattern[], maxScanChars: number): SecretReport {
  const inputTruncated = input.length > maxScanChars
  const windows = inputTruncated
    ? [
        scanWindow(input, 0, Math.floor(maxScanChars / 2), patterns),
        scanWindow(input, input.length - Math.ceil(maxScanChars / 2), Math.ceil(maxScanChars / 2), patterns),
      ]
    : [scanWindow(input, 0, input.length, patterns)]
  const findings = windows.flatMap(window => window.findings)
  const unique = new Map<string, SecretFinding>()
  for (const finding of findings) unique.set(`${finding.id}:${finding.start}:${finding.end}`, finding)
  const ordered = [...unique.values()].sort((left, right) => left.start - right.start || right.end - left.end)
  return {
    count: ordered.length,
    labels: [...new Set(ordered.map(finding => finding.id))].sort(),
    findings: ordered,
    scannedChars: Math.min(input.length, maxScanChars),
    totalChars: input.length,
    truncated: inputTruncated || windows.some(window => window.limited),
  }
}

/** Build a secret scanner that compiles its patterns exactly once. */
export function createSecretScanner(
  custom: readonly SecretPatternConfig[] = [],
  options: SecretScanOptions = {},
): (input: string) => SecretReport {
  const patterns = compileSecretPatterns(custom)
  const maxScanChars = options.maxScanChars ?? DEFAULT_MAX_SCAN_CHARS
  if (!Number.isInteger(maxScanChars) || maxScanChars < 1) {
    throw new TypeError('maxScanChars must be a positive integer')
  }
  return input => scanWithPatterns(input, patterns, maxScanChars)
}

/** Find likely credentials without retaining their values. */
export function scanSecrets(
  input: string,
  custom: readonly SecretPatternConfig[] = [],
  options: SecretScanOptions = {},
): SecretReport {
  return createSecretScanner(custom, options)(input)
}

/** Redact secret ranges with labels while preserving non-secret text. */
export function redactSecrets(input: string, report: SecretReport): string {
  if (report.truncated) return SECRET_SCAN_LIMIT_MARKER
  if (report.findings.length === 0) return input
  const ranges: Array<{ start: number; end: number; labels: Set<string> }> = []
  for (const finding of report.findings) {
    const previous = ranges.at(-1)
    if (previous !== undefined && finding.start <= previous.end) {
      previous.end = Math.max(previous.end, finding.end)
      previous.labels.add(finding.id)
    } else {
      ranges.push({ start: finding.start, end: finding.end, labels: new Set([finding.id]) })
    }
  }
  let output = ''
  let cursor = 0
  for (const range of ranges) {
    output += input.slice(cursor, range.start)
    output += `<redacted:${[...range.labels].sort().join('+')}>`
    cursor = range.end
  }
  return output + input.slice(cursor)
}
