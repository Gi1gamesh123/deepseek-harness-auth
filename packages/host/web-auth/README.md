# @deepseek-ai/dsh-host-web-auth

English | [中文](README.zh.md)

Host-level login authentication for `dsh-host-webserver`. The plugin registers `/auth/login`, `/auth/session`, and `/auth/logout`, then installs a global guard before every HTTP route, SPA fallback, and WebSocket upgrade. Existing route plugins remain unchanged. Configure `passwordEnv` with a credential reference such as `DSH_WEB_PASSWORD`; the password is resolved through `ctx.credentials` and is never stored in cordis configuration. An enabled plugin fails during boot when that reference is not configured, so a public Web process cannot start with an unusable login boundary.

Sessions are opaque random tokens stored only in memory and represented by SHA-256 digests. They expire after `sessionTtlSeconds` and all sessions disappear on process restart. Login uses a CSRF double-submit cookie, applies security headers to its HTML, and limits each remote address to `loginAttemptLimit` failed attempts per `loginAttemptWindowSeconds`. Logout accepts only POST requests carrying the CSRF token in `X-DSH-CSRF`. `secureCookie` should be enabled when HTTPS terminates in front of the process; it is disabled by default so direct HTTP access on a trusted LAN works.

## Configuration

```yaml
- id: web-auth
  name: '@deepseek-ai/dsh-host-web-auth'
  config:
    username: admin
    passwordEnv: DSH_WEB_PASSWORD
    sessionTtlSeconds: 43200
    loginAttemptLimit: 5
    loginAttemptWindowSeconds: 300
    secureCookie: false
```

The web bundle enables this plugin for every bind address, including `127.0.0.1`. A reverse proxy can expose a loopback listener publicly, so the bind address never disables authentication. Binding plain HTTP to a public network is not a TLS deployment; use HTTPS termination or a private network, and keep the authentication guard enabled behind the proxy.

## Model Experience

None, as authentication is a host transport concern and contributes no prompt, tool, message, or provider request.

#### KV Cache effect

None; sessions and credentials do not enter model requests.

## Known Limitations and Deferred Work

- Sessions are process-local and are invalidated by a restart.
- This plugin does not provide TLS; direct HTTP is appropriate only on a trusted network, while public deployment requires an HTTPS reverse proxy or VPN.
- Login throttling is local to one process and remote address, so a distributed deployment needs an upstream rate limiter.
