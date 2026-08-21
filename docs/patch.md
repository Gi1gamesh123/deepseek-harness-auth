# Public Web authentication patch

English | [中文](patch.zh.md)

This document is the update checklist for the authenticated Web customization. It records the security invariant, the public-bind command, and the checks to repeat after pulling upstream changes.

## Security invariant

The shipped `web` profile must satisfy all of these conditions:

- `web-auth` is enabled for every bind address. The value of `Host`, `Origin`, `trustedHosts`, or a proxy connection does not authenticate a user.
- `webserver.requireGuard` is `true`. A Web server without a registered guard fails closed instead of serving routes.
- Unauthenticated HTTP requests to `/api/*` return `401`; unauthenticated browser requests redirect to `/auth/login`; unauthenticated WebSocket upgrades are rejected with `401`.
- The login password is resolved from the `DSH_WEB_PASSWORD` credential reference. If it is missing, startup fails instead of starting an unprotected or unusable service.
- The public Web permission defaults are `read-only` with approval prompts. Do not copy a private profile's `danger-full-access` setting into the public profile.
- The authenticated-authority gate also covers filesystem discovery/mutation (`host.describe`, `host.listDirectory`, `host.createDirectory`), session exports, and both live event-stream upgrades. These surfaces are not anonymous just because they are reads or physical download/upgrade routes.
- When `authenticatedHosts` is configured for a public bind, it gates the entire `/api` transport, including future plugin-defined Remote endpoints; a newly installed host runner cannot silently bypass the login layer.

This closes the unauthenticated access path in the shipped Web profile, including the loopback-plus-proxy case. It does not protect a deployment whose own patch disables `web-auth`, sets `requireGuard: false`, or exposes a stolen valid session/password. Those are deployment or credential-compromise cases, not Host-header authentication.

## Enable public mode

From a clean checkout:

```sh
pnpm install
export DEEPSEEK_API_KEY='replace-with-a-rotated-key'
export DSH_WEB_PASSWORD='replace-with-a-long-random-password'
pnpm run build
pnpm dsh web --host 0.0.0.0 --port 3080
```

Open `http://<server-ip>:3080/` and sign in as `admin` with the value of `DSH_WEB_PASSWORD`. The same authentication guard is active when the Web profile binds to `127.0.0.1`.

For a service manager, keep both secrets in its environment configuration and keep them out of `cordis.yml`, shell history, logs, and Git. The service command must use the built checkout and must retain `--host 0.0.0.0` when public binding is intended.

## Verify after an update

Run the focused checks before starting the service:

```sh
pnpm run verify-cordis-config
pnpm exec vitest run \
  packages/bundle/web-app/tests/security-composition.spec.ts \
  packages/host/web-auth/tests/web-auth.spec.ts \
  packages/host/webserver/tests/webserver.spec.ts
pnpm run build
```

With the service running, an unauthenticated request must remain denied:

```sh
curl -i http://127.0.0.1:3080/api/settings.describe
curl -i http://127.0.0.1:3080/
```

The first response must be `401`. The second response must be a redirect to `/auth/login`, not the application shell. After a normal login, the browser's authenticated API calls may return `2xx`.

## Reapply after pulling upstream

1. Pull with `git pull --ff-only` and inspect conflicts in `packages/bundle/web-app/cordis.patch.yml` and `packages/host/web-auth/`.
2. Preserve the Web rows `web-auth.enabled: true`, `webserver.requireGuard: true`, `sandbox-policy.mode: read-only`, and `approval.policy: ask`.
3. Preserve the missing-password boot failure in `packages/host/web-auth/src/index.ts`.
4. Run the focused checks, `pnpm run typecheck`, and `pnpm run doc-sync`.
5. Rotate any key that was exposed before this patch. Never put the replacement value in this document.

Do not use `trustedHosts` as an authentication substitute. It is a browser-origin and DNS-rebinding defense, not proof of user identity.
