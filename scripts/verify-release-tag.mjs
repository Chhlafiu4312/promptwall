import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const args = process.argv.slice(2).filter((argument) => argument !== '--')
const tag = args.length === 1 ? args[0] : undefined
const expected = `v${packageJson.version}`

if (tag !== expected) {
  console.error(`release tag ${JSON.stringify(tag)} does not match package version ${JSON.stringify(expected)}`)
  process.exit(1)
}

console.log(`release tag verified: ${tag}`)
