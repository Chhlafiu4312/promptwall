/**
 * PromptWall runtime boundary and Cordis activation.
 * @module dsh-promptwall/runtime
 */

import type { Context } from '@deepseek-ai/cordis'
import { resolveConfig, type Config } from './config.ts'
import { createPromptWallEngine, inspectPostDecision, inspectPreDecision } from './policy.ts'
import { createPromptWallTool } from './tool.ts'

/** Fakeable host boundary used by the minimal plugin behavior. */
export interface PluginRuntime {
  /** Publish one informational message through the host. */
  info(message: string): void
  /** Publish one warning without including matched payload values. */
  warn(message: string): void
}

/**
 * Create the production runtime adapter from a scoped Cordis context.
 * @param ctx - Scoped plugin context.
 * @returns Host behavior used by the plugin implementation.
 */
export function createPluginRuntime(ctx: Context): PluginRuntime {
  return {
    info: message => { ctx.logger.info(message) },
    warn: message => { ctx.logger.warn(message) },
  }
}

/**
 * Apply the plugin to its Cordis context.
 * @param ctx - Scoped plugin context; registrations must be owned by its effects.
 * @param config - Configuration resolved by Cordis from the exported schema.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const resolved = resolveConfig(config)
  const runtime = createPluginRuntime(ctx)
  if (!resolved.enabled) {
    runtime.info('PromptWall disabled')
    return
  }
  const engine = createPromptWallEngine(resolved)
  const trustedTools = new Set(resolved.trustedTools)
  ctx.effect(() => ctx.tools.register(createPromptWallTool(engine)))

  ctx.on('tools/pre-execute', async (exec, next) => {
    const downstream = await next()
    const checked = inspectPreDecision(engine, resolved, exec, downstream)
    if (checked.secrets.count > 0) {
      runtime.warn(`PromptWall found ${checked.secrets.count} secret-like value(s) in egress arguments for ${exec.name}; labels=${checked.secrets.labels.join(',')}`)
    }
    return checked.decision
  })

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const downstream = await next()
    if (!resolved.inspectToolOutputs || trustedTools.has(exec.name)) return downstream
    const checked = inspectPostDecision(engine, resolved, exec, result, downstream)
    if (checked.inspection.findingCount > 0 || checked.inspection.secretCount > 0 || checked.inspection.truncated) {
      runtime.warn(
        `PromptWall inspected ${exec.name}: verdict=${checked.inspection.verdict}; score=${checked.inspection.score}; findings=${checked.inspection.findingCount}; secrets=${checked.inspection.secretCount}; blocked=${checked.inspection.blocked}`,
      )
    }
    return checked.decision
  })

  runtime.info('PromptWall enabled')
}
