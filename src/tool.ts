/** DSH tool definition and stable PromptWall report formatting. */

import { defineTool, type JsonValue, type ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { PromptWallEngine } from './policy.ts'

/** JSON-safe result returned by `promptwall_scan`. */
export interface PromptWallToolResult {
  readonly verdict: 'clean' | 'suspicious' | 'dangerous'
  readonly score: number
  readonly totalChars: number
  readonly scannedChars: number
  readonly truncated: boolean
  readonly findingCount: number
  readonly findings: readonly {
    readonly ruleId: string
    readonly category: string
    readonly severity: string
    readonly description: string
    readonly start: number
    readonly end: number
    readonly excerpt: string
  }[]
  readonly secretCount: number
  readonly secretLabels: readonly string[]
  readonly sanitizedText: string | null
  readonly limitation: string
}

/** Render a compact, model-visible Markdown receipt without raw secret values. */
export function formatPromptWallReport(result: PromptWallToolResult): string {
  const lines = [
    `# PromptWall: ${result.verdict.toUpperCase()} (${result.score}/100)`,
    '',
    `- Injection findings: ${result.findingCount}`,
    `- Secret-like values: ${result.secretCount}`,
    `- Scanned: ${result.scannedChars}/${result.totalChars} characters${result.truncated ? ' (limit exceeded)' : ''}`,
  ]
  if (result.findings.length > 0) {
    lines.push('', '## Findings')
    for (const finding of result.findings) {
      lines.push(`- **${finding.ruleId}** · ${finding.severity} · ${finding.description}`)
    }
  }
  if (result.secretLabels.length > 0) lines.push('', `Secret labels: ${result.secretLabels.join(', ')}`)
  lines.push('', `Limitation: ${result.limitation}`)
  if (result.sanitizedText !== null) lines.push('', '## Sanitized text', '', result.sanitizedText)
  return lines.join('\n')
}

function scanResult(engine: PromptWallEngine, text: string, includeSanitized: boolean): PromptWallToolResult {
  const checked = engine.inspectText(text)
  const sanitizedExcerpt = (excerpt: string): string => engine.inspectText(excerpt).value
  return {
    verdict: checked.injection.verdict,
    score: checked.injection.score,
    totalChars: checked.injection.totalChars,
    scannedChars: checked.injection.scannedChars,
    truncated: checked.injection.truncated,
    findingCount: checked.injection.findings.length,
    findings: checked.injection.findings.map(finding => ({ ...finding, excerpt: sanitizedExcerpt(finding.excerpt) })),
    secretCount: checked.secrets.count,
    secretLabels: checked.secrets.labels,
    sanitizedText: includeSanitized && !checked.injection.truncated ? checked.value : null,
    limitation: 'Pattern matches indicate risk; they do not prove malicious intent. Truncated content is unsafe to pass through automatically.',
  }
}

/** Create the deterministic scanner tool registered by PromptWall. */
export function createPromptWallTool(engine: PromptWallEngine): ToolDefinition {
  return defineTool({
    name: 'promptwall_scan',
    description: 'Scan untrusted text locally for prompt injection, role hijacking, system-prompt theft, secret exfiltration, tool coercion, persistence attempts, obfuscation, and high-confidence credentials. Does not execute or upload the text.',
    parameters: {
      text: {
        type: 'string',
        required: true,
        description: 'Untrusted text to inspect.',
      },
      includeSanitized: {
        type: 'boolean',
        description: 'Include a quarantined and secret-redacted copy when the configured scan limit was not exceeded.',
      },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => [{ type: 'text', text: formatPromptWallReport(value as unknown as PromptWallToolResult) }],
      presentationMeta: (_args, value) => {
        const result = value as unknown as PromptWallToolResult
        return { verdict: result.verdict, score: result.score, findings: result.findingCount, secrets: result.secretCount }
      },
    },
    execute: (args) => Promise.resolve(scanResult(engine, args.text, args.includeSanitized ?? false) as unknown as JsonValue),
    isConcurrencySafe: () => true,
  })
}
