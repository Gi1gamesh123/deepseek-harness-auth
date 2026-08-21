/**
 * @deepseek-ai/dsh-host-web-auth — host-level browser authentication for a
 * webserver composition. Credentials are resolved through `ctx.credentials`;
 * sessions are opaque, in-memory tokens and never enter the session log.
 * @module @deepseek-ai/dsh-host-web-auth
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import type { CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { WebGuard } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-credentials'
import type {} from '@deepseek-ai/dsh-host-webserver'

/** Stable Cordis plugin name. */
export const name = 'web-auth'

/** Services required before the guard and auth routes can be installed. */
export const inject = ['webServer', 'credentials']

/** Web authentication configuration. */
export interface Config {
  /** Login name accepted by the form. */
  username: string
  /** Credential reference containing the login password. */
  passwordEnv: string
  /** Lifetime of an in-memory session in seconds. */
  sessionTtlSeconds: number
  /** Failed login attempts allowed per remote address and window. */
  loginAttemptLimit: number
  /** Failed-login counting window in seconds. */
  loginAttemptWindowSeconds: number
  /** Add Secure to cookies when the deployment is served through HTTPS. */
  secureCookie: boolean
  /** Disable the plugin when a composition supplies its own authentication. */
  enabled: boolean
}

export const Config: z<Config> = z.object({
  username: z.string().min(1).default('admin'),
  passwordEnv: z.string().min(1).default('DSH_WEB_PASSWORD'),
  sessionTtlSeconds: z.natural().min(60).max(604800).default(43200),
  loginAttemptLimit: z.natural().min(1).max(100).default(5),
  loginAttemptWindowSeconds: z.natural().min(10).max(3600).default(300),
  secureCookie: z.boolean().default(false),
  enabled: z.boolean().default(true),
})

const SESSION_COOKIE = 'dsh_session'
const CSRF_COOKIE = 'dsh_csrf'
const MAX_BODY_BYTES = 16 * 1024

interface Session {
  username: string
  expiresAt: number
}

interface LoginFailures {
  count: number
  expiresAt: number
}

interface Runtime {
  readonly passwordRef: CredentialRef
  readonly sessions: Map<string, Session>
  readonly loginFailures: Map<string, LoginFailures>
  readonly config: Config
}

function token(): string {
  return randomBytes(32).toString('base64url')
}

function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}

function cookies(req: IncomingMessage): Map<string, string> {
  const result = new Map<string, string>()
  for (const part of req.headers.cookie?.split(';') ?? []) {
    const at = part.indexOf('=')
    if (at === -1) continue
    result.set(part.slice(0, at).trim(), part.slice(at + 1).trim())
  }
  return result
}

function cookieValue(req: IncomingMessage, name: string): string | undefined {
  return cookies(req).get(name)
}

function appendCookie(res: ServerResponse, value: string): void {
  const previous = res.getHeader('set-cookie')
  const values = Array.isArray(previous) ? previous.map(String) : previous === undefined ? [] : [String(previous)]
  res.setHeader('set-cookie', [...values, value])
}

function cookie(name: string, value: string, config: Config, httpOnly: boolean, maxAge?: number): string {
  return `${name}=${value}; Path=/; SameSite=Lax${httpOnly ? '; HttpOnly' : ''}`
    + `${config.secureCookie ? '; Secure' : ''}${maxAge === undefined ? '' : `; Max-Age=${String(maxAge)}`}`
}

function clearCookie(name: string, config: Config): string {
  return `${name}=; Path=/; SameSite=Lax${config.secureCookie ? '; Secure' : ''}; Max-Age=0`
}

function writeJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(value))
}

function htmlHeaders(): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), geolocation=(), microphone=()',
  }
}

function writeUnauthorizedUpgrade(socket: Duplex): void {
  socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
}

function nextPath(raw: string | null): string {
  if (raw === null || raw.length === 0 || !raw.startsWith('/') || raw.startsWith('//')) return '/'
  try {
    const parsed = new URL(raw, 'http://dsh.invalid')
    return parsed.origin === 'http://dsh.invalid' ? `${parsed.pathname}${parsed.search}${parsed.hash}` : '/'
  } catch {
    return '/'
  }
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] as string)
}

async function readBody(req: IncomingMessage): Promise<string | undefined> {
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buffer.length
    if (size > MAX_BODY_BYTES) return undefined
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function sessionOf(runtime: Runtime, req: IncomingMessage): Session | undefined {
  const raw = cookieValue(req, SESSION_COOKIE)
  if (raw === undefined) return undefined
  const key = digest(raw)
  const session = runtime.sessions.get(key)
  if (session === undefined) return undefined
  if (session.expiresAt <= Date.now()) {
    runtime.sessions.delete(key)
    return undefined
  }
  return session
}

function loginFailureKey(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown'
}

function retryAfter(runtime: Runtime, req: IncomingMessage, now = Date.now()): number | undefined {
  const key = loginFailureKey(req)
  const failures = runtime.loginFailures.get(key)
  if (failures === undefined) return undefined
  if (failures.expiresAt <= now) {
    runtime.loginFailures.delete(key)
    return undefined
  }
  if (failures.count < runtime.config.loginAttemptLimit) return undefined
  return Math.max(1, Math.ceil((failures.expiresAt - now) / 1000))
}

function recordLoginFailure(runtime: Runtime, req: IncomingMessage, now = Date.now()): void {
  const key = loginFailureKey(req)
  const current = runtime.loginFailures.get(key)
  if (current === undefined || current.expiresAt <= now) {
    runtime.loginFailures.set(key, {
      count: 1,
      expiresAt: now + runtime.config.loginAttemptWindowSeconds * 1000,
    })
    return
  }
  current.count++
}

function redirectLogin(req: IncomingMessage, res: ServerResponse): void {
  const rawPath = new URL(req.url ?? '/', 'http://dsh.invalid').pathname
  const query = rawPath === '/auth/login' ? '' : `?next=${encodeURIComponent(`${rawPath}${new URL(req.url ?? '/', 'http://dsh.invalid').search}`)}`
  res.writeHead(302, { location: `/auth/login${query}`, 'cache-control': 'no-store' })
  res.end()
}

function loginPage(next: string, csrf: string, error?: string): string {
  const message = error === undefined ? '' : `<p class="auth-error" role="alert"><span aria-hidden="true">!</span>${escapeHtml(error)}</p>`
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f5f7fb"><title>Sign in · DeepSeek Harness</title><style>
 :root { color-scheme: light; --auth-bg: #f5f7fb; --auth-bg-accent: rgba(65,118,230,.14); --auth-card: rgba(255,255,255,.86); --auth-card-border: rgba(15,23,42,.08); --auth-ink: #0f172a; --auth-muted: #667085; --auth-faint: #98a2b3; --auth-field: rgba(248,250,252,.92); --auth-field-border: #d9e0eb; --auth-focus: #4176e6; --auth-button: #0f172a; --auth-button-ink: #fff; --auth-button-hover: #27334a; --auth-error-bg: #fff3f2; --auth-error-border: #f7c8c3; --auth-error-ink: #b42318; --auth-shadow: 0 24px 70px rgba(15,23,42,.12); --auth-font: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'Helvetica Neue', Arial, sans-serif; }
@media (prefers-color-scheme: dark) { :root { color-scheme: dark; --auth-bg: #15171c; --auth-bg-accent: rgba(86,134,254,.18); --auth-card: rgba(29,31,36,.88); --auth-card-border: rgba(255,255,255,.1); --auth-ink: #f5f7fb; --auth-muted: #a6adbb; --auth-faint: #777f8d; --auth-field: rgba(21,23,28,.86); --auth-field-border: #3b414d; --auth-focus: #7098ff; --auth-button: #f5f7fb; --auth-button-ink: #15171c; --auth-button-hover: #dce6ff; --auth-error-bg: rgba(180,35,24,.16); --auth-error-border: rgba(247,200,195,.32); --auth-error-ink: #ffb4ab; --auth-shadow: 0 24px 70px rgba(0,0,0,.34); } }
* { box-sizing: border-box; } html, body { min-height: 100%; margin: 0; } body { min-height: 100vh; color: var(--auth-ink); background: radial-gradient(circle at 8% 5%, var(--auth-bg-accent), transparent 32%), radial-gradient(circle at 94% 96%, rgba(103,158,254,.1), transparent 29%), var(--auth-bg); font-family: var(--auth-font); -webkit-font-smoothing: antialiased; }
.auth-shell { width: min(100% - 48px, 1040px); min-height: 100vh; margin: 0 auto; display: grid; grid-template-columns: minmax(0, 1fr) 420px; align-items: center; gap: clamp(44px, 8vw, 108px); padding: 48px 0; }
.auth-intro { padding: 18px 0; } .brand { display: flex; align-items: center; gap: 14px; margin-bottom: 34px; } .brand-mark { width: 46px; height: 46px; display: grid; place-items: center; border-radius: 15px; color: #fff; background: linear-gradient(145deg, #5686fe, #315bbd); box-shadow: 0 10px 24px rgba(65,118,230,.28); font-size: 14px; font-weight: 700; letter-spacing: .08em; } .brand-name { font-size: 18px; font-weight: 600; letter-spacing: -.02em; } .brand-kicker { margin-top: 3px; color: var(--auth-faint); font-size: 11px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; }
.auth-intro h1 { max-width: 480px; margin: 0; font-size: clamp(38px, 5vw, 58px); line-height: 1.08; letter-spacing: -.055em; } .auth-intro-copy { max-width: 430px; margin: 22px 0 0; color: var(--auth-muted); font-size: 17px; line-height: 1.65; }
.auth-pills { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 30px; } .auth-pill { padding: 7px 11px; border: 1px solid var(--auth-card-border); border-radius: 999px; color: var(--auth-muted); background: var(--auth-card); font-size: 12px; }
.auth-card { padding: clamp(28px, 5vw, 42px); border: 1px solid var(--auth-card-border); border-radius: 24px; background: var(--auth-card); box-shadow: var(--auth-shadow); } .auth-card h2 { margin: 0; font-size: 25px; letter-spacing: -.035em; } .auth-card-copy { margin: 9px 0 27px; color: var(--auth-muted); font-size: 14px; line-height: 1.5; }
.auth-form { display: grid; gap: 17px; } .auth-field { display: grid; gap: 8px; } .auth-field label { color: var(--auth-muted); font-size: 13px; font-weight: 600; } .auth-field input { width: 100%; height: 46px; padding: 0 13px; border: 1px solid var(--auth-field-border); border-radius: 11px; outline: none; color: var(--auth-ink); background: var(--auth-field); font: inherit; font-size: 15px; transition: border-color .18s ease, box-shadow .18s ease, background .18s ease; } .auth-field input::placeholder { color: var(--auth-faint); } .auth-field input:focus { border-color: var(--auth-focus); background: var(--auth-card); box-shadow: 0 0 0 4px rgba(65,118,230,.18); }
.auth-error { display: flex; align-items: flex-start; gap: 9px; margin: 0 0 19px; padding: 11px 12px; border: 1px solid var(--auth-error-border); border-radius: 11px; color: var(--auth-error-ink); background: var(--auth-error-bg); font-size: 13px; line-height: 1.45; } .auth-error span { flex: 0 0 auto; width: 17px; height: 17px; border: 1px solid currentColor; border-radius: 50%; text-align: center; font-size: 12px; font-weight: 700; line-height: 15px; }
.auth-submit { display: flex; align-items: center; justify-content: center; gap: 9px; width: 100%; height: 46px; margin-top: 4px; border: 0; border-radius: 11px; color: var(--auth-button-ink); background: var(--auth-button); cursor: pointer; font: inherit; font-size: 14px; font-weight: 600; transition: background .18s ease, transform .18s ease, box-shadow .18s ease; } .auth-submit:hover { background: var(--auth-button-hover); box-shadow: 0 8px 18px rgba(15,23,42,.16); transform: translateY(-1px); } .auth-submit:focus-visible { outline: 3px solid rgba(65,118,230,.38); outline-offset: 3px; } .auth-submit-arrow { font-size: 18px; line-height: 1; }
.auth-footer { margin: 24px 0 0; color: var(--auth-faint); font-size: 12px; text-align: center; }
@media (max-width: 760px) { .auth-shell { display: block; width: min(100% - 32px, 460px); padding: 28px 0; } .auth-intro { padding: 8px 0 28px; } .brand { margin-bottom: 25px; } .auth-intro h1 { font-size: 35px; } .auth-intro-copy { margin-top: 12px; font-size: 15px; } .auth-pills { display: none; } .auth-card { padding: 27px 22px; } }
</style></head><body><main class="auth-shell"><section class="auth-intro" aria-label="DeepSeek Harness"><div class="brand"><div class="brand-mark" aria-hidden="true">DSH</div><div><div class="brand-name">DeepSeek Harness</div><div class="brand-kicker">Private coding workspace</div></div></div><h1>Build boldly.<br>Stay in control.</h1><p class="auth-intro-copy">A focused workspace for agentic coding, tools, and your own plugin stack.</p><div class="auth-pills" aria-hidden="true"><span class="auth-pill">Secure by default</span><span class="auth-pill">Plugin-ready</span><span class="auth-pill">Local-first</span></div></section><section class="auth-card" aria-labelledby="auth-title"><h2 id="auth-title">Welcome back</h2><p class="auth-card-copy">Sign in to continue to your workspace.</p>${message}<form class="auth-form" method="post" action="/auth/login"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="next" value="${escapeHtml(next)}"><div class="auth-field"><label for="username">Username</label><input id="username" name="username" autocomplete="username" placeholder="Enter your username" required></div><div class="auth-field"><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" placeholder="Enter your password" required></div><button class="auth-submit" type="submit"><span>Sign in</span><span class="auth-submit-arrow" aria-hidden="true">→</span></button></form><p class="auth-footer">DeepSeek Harness · Your workspace stays yours</p></section></main></body></html>`
}

function authGuard(runtime: Runtime): WebGuard {
  const allowAuth = (req: IncomingMessage): boolean => {
    const pathname = new URL(req.url ?? '/', 'http://dsh.invalid').pathname
    return pathname === '/auth/login' || pathname === '/auth/session' || pathname === '/auth/logout'
  }
  return {
    http: (req, res) => {
      if (allowAuth(req) || sessionOf(runtime, req) !== undefined) return true
      const pathname = new URL(req.url ?? '/', 'http://dsh.invalid').pathname
      if (pathname === '/api' || pathname.startsWith('/api/')) {
        writeJson(res, 401, { error: 'authentication required' })
      } else {
        redirectLogin(req, res)
      }
      return false
    },
    upgrade: (req, socket) => {
      if (sessionOf(runtime, req) !== undefined) return true
      writeUnauthorizedUpgrade(socket)
      return false
    },
  }
}

/** Install the login routes and the global WebServer guard. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  if (!config.enabled) return
  const passwordRef = credentialRef(config.passwordEnv)
  const passwordInfo = await ctx.credentials.describe(passwordRef)
  if (!passwordInfo.configured) {
    throw new Error(`web-auth: password credential ${config.passwordEnv} is not configured`)
  }
  const runtime: Runtime = {
    passwordRef,
    sessions: new Map(),
    loginFailures: new Map(),
    config,
  }
  const guard = authGuard(runtime)
  ctx.effect(() => {
    const disposeGuard = ctx.webServer.registerGuard(guard)
    const disposeLogin = ctx.webServer.register({ kind: 'exact', path: '/auth/login', handler: async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://dsh.invalid')
      if (req.method === 'GET' || req.method === 'HEAD') {
        // Reuse the browser's existing token when the page is requested again.
        // Rotating it on every GET lets a second tab or a duplicate navigation
        // invalidate the first form before the user submits it.
        const existingCsrf = cookieValue(req, CSRF_COOKIE)
        const csrf = existingCsrf ?? token()
        if (existingCsrf === undefined) {
          appendCookie(res, cookie(CSRF_COOKIE, csrf, config, false))
        }
        res.writeHead(200, htmlHeaders())
        res.end(req.method === 'HEAD' ? undefined : loginPage(nextPath(url.searchParams.get('next')), csrf))
        return
      }
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'GET, HEAD, POST' })
        res.end()
        return
      }
      const body = await readBody(req)
      if (body === undefined) {
        res.writeHead(413)
        res.end()
        return
      }
      const form = new URLSearchParams(body)
      const csrf = cookieValue(req, CSRF_COOKIE)
      if (csrf === undefined || !equalSecret(csrf, form.get('csrf') ?? '')) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('invalid csrf token')
        return
      }
      const wait = retryAfter(runtime, req)
      if (wait !== undefined) {
        res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(wait) })
        res.end('too many login attempts')
        return
      }
      const credential = await ctx.credentials.resolve(runtime.passwordRef)
      const valid = credential !== undefined
        && form.get('username') === config.username
        && equalSecret(form.get('password') ?? '', credential.value)
      if (!valid) {
        recordLoginFailure(runtime, req)
        res.writeHead(401, htmlHeaders())
        res.end(loginPage(nextPath(form.get('next')), csrf, 'Invalid username or password'))
        return
      }
      runtime.loginFailures.delete(loginFailureKey(req))
      const session = token()
      runtime.sessions.set(digest(session), { username: config.username, expiresAt: Date.now() + config.sessionTtlSeconds * 1000 })
      appendCookie(res, cookie(SESSION_COOKIE, session, config, true, config.sessionTtlSeconds))
      res.writeHead(302, { location: nextPath(form.get('next')), 'cache-control': 'no-store' })
      res.end()
    } })
    const disposeSession = ctx.webServer.register({ kind: 'exact', path: '/auth/session', handler: (req, res) => {
      const session = sessionOf(runtime, req)
      writeJson(res, 200, session === undefined ? { authenticated: false } : { authenticated: true, username: session.username })
    } })
    const disposeLogout = ctx.webServer.register({ kind: 'exact', path: '/auth/logout', handler: (req, res) => {
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' })
        res.end()
        return
      }
      const csrf = cookieValue(req, CSRF_COOKIE)
      const presented = req.headers['x-dsh-csrf']
      if (csrf === undefined || typeof presented !== 'string' || !equalSecret(csrf, presented)) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
        res.end('invalid csrf token')
        return
      }
      const raw = cookieValue(req, SESSION_COOKIE)
      if (raw !== undefined) runtime.sessions.delete(digest(raw))
      appendCookie(res, clearCookie(SESSION_COOKIE, config))
      appendCookie(res, clearCookie(CSRF_COOKIE, config))
      res.writeHead(204, { 'cache-control': 'no-store' })
      res.end()
    } })
    const timer = setInterval(() => {
      const now = Date.now()
      for (const [key, session] of runtime.sessions) if (session.expiresAt <= now) runtime.sessions.delete(key)
      for (const [key, failures] of runtime.loginFailures) if (failures.expiresAt <= now) runtime.loginFailures.delete(key)
    }, Math.min(config.sessionTtlSeconds, config.loginAttemptWindowSeconds, 60) * 1000)
    timer.unref()
    return () => {
      clearInterval(timer)
      disposeLogout()
      disposeSession()
      disposeLogin()
      disposeGuard()
    }
  }, 'web-auth')
}
