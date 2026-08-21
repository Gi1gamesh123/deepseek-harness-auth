import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { pathToFileURL } from 'node:url'
import { connect } from 'node:net'
import { once } from 'node:events'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'
import { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { CredentialInfo, CredentialRef, ResolvedCredential } from '@deepseek-ai/dsh-credentials'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import * as WebAuth from '../src/index.ts'

class TestCredentials extends CredentialProvider {
  override resolve(ref: CredentialRef): Promise<ResolvedCredential | undefined> {
    return Promise.resolve(ref === 'DSH_WEB_PASSWORD' ? { value: 'correct horse battery staple', source: 'test' } : undefined)
  }
  override describe(ref: CredentialRef): Promise<CredentialInfo> {
    return Promise.resolve({ configured: ref === 'DSH_WEB_PASSWORD', source: 'test', writable: false })
  }
  override set(): Promise<void> { return Promise.reject(new Error('read-only test provider')) }
  override unset(): Promise<void> { return Promise.resolve() }
}

let context: Context | undefined
let root: string | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

async function loadComposition(): Promise<Context> {
  root = await mkdtemp(join(tmpdir(), 'dsh-web-auth-loader-'))
  const configPath = join(root, 'cordis.yml')
  await writeFile(configPath, [
    "- name: 'test-credentials'",
    "- name: '@deepseek-ai/dsh-host-webserver'",
    '  config:',
    "    host: '127.0.0.1'",
    '    port: 0',
    "- name: '@deepseek-ai/dsh-host-web-auth'",
    '  config:',
    '    username: admin',
    '    passwordEnv: DSH_WEB_PASSWORD',
    '',
  ].join('\n'))
  context = new Context()
  context.baseUrl = pathToFileURL(root).href + '/'
  await context.plugin(Loader)
  context.loader.builtins.include = Include
  const modules = new Map<string, unknown>([
    ['test-credentials', TestCredentials],
    ['@deepseek-ai/dsh-host-webserver', WebServer],
    ['@deepseek-ai/dsh-host-web-auth', { name: 'web-auth', inject: ['webServer', 'credentials'], Config: WebAuth.Config, apply: WebAuth.apply }],
  ])
  context.loader.internal = {
    version: 'v2',
    async import(specifier: string) {
      if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
      return modules.get(specifier)
    },
  } as unknown as NonNullable<typeof context.loader.internal>
  await context.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } })
  await context.loader.await()
  return context
}

function cookiePair(value: string | null, name: string): string {
  const match = value?.split(/, (?=[^;=]+=[^;]+)/).find(item => item.startsWith(`${name}=`))
  if (match === undefined) throw new Error(`missing ${name} cookie`)
  const pair = match.split(';', 1)[0]
  if (pair === undefined) throw new Error(`missing ${name} cookie value`)
  return pair
}

describe('web-auth real composition', () => {
  it('fails closed when the configured password is absent', { timeout: 60_000 }, async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-web-auth-missing-'))
    const configPath = join(root, 'cordis.yml')
    await writeFile(configPath, [
      "- name: 'missing-credentials'",
      "- name: '@deepseek-ai/dsh-host-webserver'",
      '  config:',
      "    host: '127.0.0.1'",
      '    port: 0',
      "- name: '@deepseek-ai/dsh-host-web-auth'",
      '  config:',
      '    passwordEnv: DSH_MISSING_WEB_PASSWORD',
      '',
    ].join('\n'))
    context = new Context()
    context.baseUrl = pathToFileURL(root).href + '/'
    await context.plugin(Loader)
    context.loader.builtins.include = Include
    const modules = new Map<string, unknown>([
      ['missing-credentials', TestCredentials],
      ['@deepseek-ai/dsh-host-webserver', WebServer],
      ['@deepseek-ai/dsh-host-web-auth', { name: 'web-auth', inject: ['webServer', 'credentials'], Config: WebAuth.Config, apply: WebAuth.apply }],
    ])
    context.loader.internal = {
      version: 'v2',
      async import(specifier: string) {
        if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
        return modules.get(specifier)
      },
    } as unknown as NonNullable<typeof context.loader.internal>
    await context.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } })
    await expect(context.loader.await()).rejects.toThrow('password credential DSH_MISSING_WEB_PASSWORD is not configured')
  })

  it('protects routes, performs CSRF login, and invalidates logout sessions', { timeout: 60_000 }, async () => {
    const loaded = await loadComposition()
    loaded.webServer.register({ kind: 'prefix', path: '/api', handler: (_req, res) => { res.writeHead(200); res.end('protected') } })
    const base = `http://127.0.0.1:${String(loaded.webServer.port)}`

    expect((await fetch(`${base}/api/test`)).status).toBe(401)
    expect((await fetch(`${base}/api/events.mux`)).status).toBe(401)
    expect((await fetch(`${base}/api/session.export?sessionId=missing`)).status).toBe(401)
    expect((await fetch(`${base}/plugins/example/client.js`, { redirect: 'manual' })).status).toBe(302)
    expect((await fetch(`${base}/api%2Fsession.list`, { redirect: 'manual' })).status).toBe(302)
    const upgrade = connect(loaded.webServer.port, '127.0.0.1')
    await once(upgrade, 'connect')
    const upgradeResponse = once(upgrade, 'data')
    upgrade.write('GET /api/socket HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: dsh-test\r\n\r\n')
    const [upgradeData] = await upgradeResponse as [Buffer]
    expect(String(upgradeData)).toContain('401 Unauthorized')
    upgrade.destroy()
    expect((await fetch(`${base}/`, { redirect: 'manual' })).status).toBe(302)

    const loginPage = await fetch(`${base}/auth/login?next=%2Fapi%2Ftest`)
    expect(loginPage.status).toBe(200)
    expect(loginPage.headers.get('content-security-policy')).toContain("style-src 'unsafe-inline'")
    expect(loginPage.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
    expect(loginPage.headers.get('x-frame-options')).toBe('DENY')
    expect(await loginPage.text()).toContain('class="auth-card"')
    const csrfCookie = cookiePair(loginPage.headers.get('set-cookie'), 'dsh_csrf')
    const csrf = csrfCookie.slice('dsh_csrf='.length)
    const repeatedLoginPage = await fetch(`${base}/auth/login?next=%2Fapi%2Ftest`, {
      headers: { cookie: csrfCookie },
    })
    expect(repeatedLoginPage.headers.get('set-cookie')).toBeNull()
    const denied = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: csrfCookie },
      body: new URLSearchParams({ username: 'admin', password: 'correct horse battery staple', csrf: 'wrong' }),
    })
    expect(denied.status).toBe(403)

    const login = await fetch(`${base}/auth/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: csrfCookie },
      body: new URLSearchParams({ username: 'admin', password: 'correct horse battery staple', csrf, next: '/api/test' }),
    })
    expect(login.status).toBe(302)
    const sessionCookie = cookiePair(login.headers.get('set-cookie'), 'dsh_session')
    expect((await fetch(`${base}/api/test`, { headers: { cookie: sessionCookie } })).status).toBe(200)
    expect(await (await fetch(`${base}/auth/session`, { headers: { cookie: sessionCookie } })).json()).toEqual({ authenticated: true, username: 'admin' })

    expect((await fetch(`${base}/auth/logout`)).status).toBe(405)
    expect((await fetch(`${base}/auth/logout`, { method: 'POST' })).status).toBe(403)
    const logout = await fetch(`${base}/auth/logout`, {
      method: 'POST',
      headers: { cookie: `${sessionCookie}; ${csrfCookie}`, 'x-dsh-csrf': csrf },
    })
    expect(logout.status).toBe(204)
    expect((await fetch(`${base}/api/test`, { headers: { cookie: sessionCookie } })).status).toBe(401)
  })

  it('rate-limits failed login attempts by remote address', { timeout: 60_000 }, async () => {
    const loaded = await loadComposition()
    const base = `http://127.0.0.1:${String(loaded.webServer.port)}`
    const loginPage = await fetch(`${base}/auth/login`)
    const csrfCookie = cookiePair(loginPage.headers.get('set-cookie'), 'dsh_csrf')
    const csrf = csrfCookie.slice('dsh_csrf='.length)

    for (let attempt = 0; attempt < 5; attempt++) {
      const denied = await fetch(`${base}/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: csrfCookie },
        body: new URLSearchParams({ username: 'admin', password: 'wrong', csrf }),
      })
      expect(denied.status).toBe(401)
    }
    const limited = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: csrfCookie },
      body: new URLSearchParams({ username: 'admin', password: 'correct horse battery staple', csrf }),
    })
    expect(limited.status).toBe(429)
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0)
  })
})
