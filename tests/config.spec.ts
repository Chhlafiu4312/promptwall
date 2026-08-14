import { describe, expect, it } from 'vitest'
import { resolveConfig } from '../src/config.ts'

describe('PromptWall configuration', () => {
  it('resolves security-oriented defaults', () => {
    expect(resolveConfig()).toMatchObject({
      enabled: true,
      injectionAction: 'sanitize',
      egressAction: 'ask',
      inspectToolOutputs: true,
      suspiciousThreshold: 30,
      dangerousThreshold: 70,
    })
  })

  it('accepts explicit policy modes and custom caps', () => {
    expect(resolveConfig({ injectionAction: 'block', egressAction: 'deny', maxScanChars: 4_096 })).toMatchObject({
      injectionAction: 'block',
      egressAction: 'deny',
      maxScanChars: 4_096,
    })
  })

  it('rejects inverted or non-integer thresholds', () => {
    expect(() => resolveConfig({ suspiciousThreshold: 80, dangerousThreshold: 70 })).toThrow('lower than')
    expect(() => resolveConfig({ maxScanChars: 1_024.5 })).toThrow('integer')
  })
})
