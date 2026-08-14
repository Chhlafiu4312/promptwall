import { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import { vi } from 'vitest'
import * as plugin from '../src/index.ts'

/** Mount the production plugin with an observable host logger. */
export async function createPluginHarness(config: plugin.Config = {}) {
  const ctx = new Context()
  const tools = new Map<string, ToolDefinition>()
  const removeTools = await ctx.provide('tools', {
    register(definition: ToolDefinition): () => void {
      if (tools.has(definition.name)) throw new Error(`duplicate tool ${definition.name}`)
      tools.set(definition.name, definition)
      return () => { tools.delete(definition.name) }
    },
  })
  const info = vi.spyOn(ctx.logger, 'info').mockImplementation(() => undefined)
  const warn = vi.spyOn(ctx.logger, 'warn').mockImplementation(() => undefined)
  const fiber = await ctx.plugin(plugin, config)

  return {
    ctx,
    fiber,
    tools,
    info,
    warn,
    async dispose(): Promise<void> {
      try {
        await fiber.dispose()
        await removeTools()
      } finally {
        info.mockRestore()
        warn.mockRestore()
      }
    },
  }
}
