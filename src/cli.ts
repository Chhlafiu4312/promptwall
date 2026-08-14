#!/usr/bin/env node
/** Standalone PromptWall CLI. */

import { readFile } from 'node:fs/promises'
import { realpathSync } from 'node:fs'
import { stdin, stdout, stderr } from 'node:process'
import { fileURLToPath } from 'node:url'
import { createPromptWallEngine } from './policy.ts'
import { resolveConfig } from './config.ts'
import { formatPromptWallReport, type PromptWallToolResult } from './tool.ts'

/** Fakeable I/O boundary for CLI tests. */
export interface CliIo {
  readFile(path: string): Promise<string>
  readStdin(): Promise<string>
  writeOut(text: string): void
  writeError(text: string): void
}

interface CliOptions {
  readonly inputText?: string
  readonly inputFile?: string
  readonly json: boolean
  readonly sanitize: boolean
  readonly maxChars: number
  readonly failOn: 'never' | 'suspicious' | 'dangerous'
  readonly help: boolean
}

const HELP = `PromptWall — local prompt-injection scanner

Usage:
  promptwall --file <path> [--json] [--sanitize]
  promptwall --text <value> [--json] [--sanitize]
  command | promptwall [--fail-on suspicious|dangerous|never]

Options:
  --file <path>       Read UTF-8 text from a file
  --text <value>      Scan a literal argument
  --json              Emit JSON instead of Markdown
  --sanitize          Include a quarantined, secret-redacted copy
  --max-chars <n>     Scan limit from 1024 to 2000000 (default 250000)
  --fail-on <level>   Exit 1 at suspicious, dangerous, or never (default dangerous)
  --help              Show this help
`

function parseInteger(value: string | undefined, option: string): number {
  if (value === undefined || !/^\d+$/u.test(value)) throw new TypeError(`${option} requires an integer`)
  return Number(value)
}

function parseArgs(argv: readonly string[]): CliOptions {
  let inputText: string | undefined
  let inputFile: string | undefined
  let json = false
  let sanitize = false
  let maxChars = 250_000
  let failOn: CliOptions['failOn'] = 'dangerous'
  let help = false
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    switch (argument) {
      case '--text':
        inputText = argv[++index]
        if (inputText === undefined) throw new TypeError('--text requires a value')
        break
      case '--file':
        inputFile = argv[++index]
        if (inputFile === undefined) throw new TypeError('--file requires a path')
        break
      case '--json': json = true; break
      case '--sanitize': sanitize = true; break
      case '--max-chars': maxChars = parseInteger(argv[++index], '--max-chars'); break
      case '--fail-on': {
        const value = argv[++index]
        if (value !== 'never' && value !== 'suspicious' && value !== 'dangerous') {
          throw new TypeError('--fail-on must be suspicious, dangerous, or never')
        }
        failOn = value
        break
      }
      case '--help':
      case '-h': help = true; break
      default: throw new TypeError(`unknown option ${JSON.stringify(argument)}`)
    }
  }
  if (inputText !== undefined && inputFile !== undefined) throw new TypeError('choose either --text or --file, not both')
  return { ...(inputText === undefined ? {} : { inputText }), ...(inputFile === undefined ? {} : { inputFile }), json, sanitize, maxChars, failOn, help }
}

async function defaultReadStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

const defaultIo: CliIo = {
  readFile: path => readFile(path, 'utf8'),
  readStdin: defaultReadStdin,
  writeOut: text => { stdout.write(text) },
  writeError: text => { stderr.write(text) },
}

/** Run the CLI and return its process exit code. */
export async function runCli(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  let options: CliOptions
  try {
    options = parseArgs(argv)
  } catch (error) {
    io.writeError(`promptwall: ${error instanceof Error ? error.message : String(error)}\n`)
    return 2
  }
  if (options.help) {
    io.writeOut(HELP)
    return 0
  }
  let text: string
  try {
    text = options.inputText ?? (options.inputFile === undefined ? await io.readStdin() : await io.readFile(options.inputFile))
  } catch (error) {
    io.writeError(`promptwall: ${error instanceof Error ? error.message : String(error)}\n`)
    return 2
  }
  if (text.length === 0) {
    io.writeError('promptwall: no input received\n')
    return 2
  }
  const engine = createPromptWallEngine(resolveConfig({ maxScanChars: options.maxChars, injectionAction: 'sanitize' }))
  const checked = engine.inspectText(text)
  const truncated = checked.injection.truncated || checked.secrets.truncated
  const result: PromptWallToolResult = {
    verdict: checked.injection.verdict,
    score: checked.injection.score,
    totalChars: checked.injection.totalChars,
    scannedChars: checked.injection.scannedChars,
    truncated,
    findingCount: checked.injection.findings.length,
    findings: checked.injection.findings.map(finding => ({ ...finding, excerpt: engine.inspectText(finding.excerpt).value })),
    secretCount: checked.secrets.count,
    secretLabels: checked.secrets.labels,
    sanitizedText: options.sanitize && !truncated ? checked.value : null,
    limitation: 'Pattern matches indicate risk; they do not prove malicious intent. Truncated content is unsafe to pass through automatically.',
  }
  io.writeOut(`${options.json ? JSON.stringify(result, null, 2) : formatPromptWallReport(result)}\n`)
  if (options.failOn === 'never') return 0
  if (options.failOn === 'suspicious') return result.verdict === 'clean' ? 0 : 1
  return result.verdict === 'dangerous' ? 1 : 0
}

let invokedDirectly = false
try {
  invokedDirectly = process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
} catch {
  invokedDirectly = false
}
if (invokedDirectly) {
  process.exitCode = await runCli(process.argv.slice(2))
}
