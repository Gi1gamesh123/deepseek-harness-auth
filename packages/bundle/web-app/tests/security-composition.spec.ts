/** Security defaults in the composed Web bundle. */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import * as yaml from 'js-yaml'
import { applyEntryPatches, entryListSchema, type PatchOptions } from '@deepseek-ai/cordis-plugin-include'
import { describe, expect, it } from 'vitest'

/** Parse one bundle patch through the Loader's production YAML dialect. */
function loadPatch(path: URL): PatchOptions[] {
  const parsed: unknown = yaml.load(readFileSync(fileURLToPath(path), 'utf8'), { schema: entryListSchema })
  if (!Array.isArray(parsed)) throw new TypeError(`${path.href} must contain a patch list`)
  return parsed as PatchOptions[]
}

describe('Web bundle security composition', () => {
  it('requires authentication and pins public sessions to read-only approval mode', () => {
    const base = loadPatch(new URL('../../base/cordis.patch.yml', import.meta.url))
    const web = loadPatch(new URL('../cordis.patch.yml', import.meta.url))
    const warnings: string[] = []
    const rows = applyEntryPatches([], structuredClone([...base, ...web]), message => warnings.push(message))
    const byId = new Map(rows.map(row => [row.id, row]))

    expect(warnings).toEqual([])
    expect(byId.get('sandbox-policy')?.config).toEqual({
      mode: 'read-only',
      workspaceRoot: { __jsExpr: 'process.cwd()' },
    })
    expect(byId.get('approval')?.config).toEqual({ policy: 'ask' })
    expect(byId.get('webserver')?.config).toMatchObject({ requireGuard: true })
    expect(byId.get('web-auth')?.config).toMatchObject({
      enabled: true,
      passwordEnv: 'DSH_WEB_PASSWORD',
    })
  })
})
