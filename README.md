# DeepSeek Harness Auth

English | [中文](README.zh.md)

This repository is a downstream customization of DeepSeek Harness for self-hosted Web deployments. It adds public binding with account-password authentication and keeps the plugin-based Cordis architecture.

This is a source-only development repository. There is no prebuilt package for this customization; install dependencies and compile it locally before every deployment.

## What this repository adds

- The Web profile enables the host authentication plugin for every bind address; binding to `0.0.0.0` does not bypass it.
- The login guard covers the Web UI, API routes, SPA fallback, and WebSocket upgrades.
- The browser client uses a Linux-safe UUID fallback and recovers to the login page when a restart invalidates its session.
- Login uses a CSRF double-submit cookie, in-memory sessions, and failed-login throttling.
- The password is read from `DSH_WEB_PASSWORD`; credentials, cookies, and session tokens are not committed.

## Requirements

- Node.js `22.19` or newer, and `pnpm`.
- A `DEEPSEEK_API_KEY` for model requests.
- A long random value for `DSH_WEB_PASSWORD`.

<a id="run"></a><a id="run-from-source"></a>

## Build and run

Clone this repository and build the runtime and browser bundles locally:

```sh
git clone https://github.com/Gi1gamesh123/deepseek-harness-auth.git
cd deepseek-harness-auth
pnpm install
export DEEPSEEK_API_KEY='your-deepseek-api-key'
export DSH_WEB_PASSWORD='choose-a-long-random-password'
pnpm run build
pnpm dsh web --host 0.0.0.0 --port 3080
```

Open `http://<server-ip>:3080/` and sign in with username `admin` and the value of `DSH_WEB_PASSWORD`. The Web profile requires this login on both loopback and all-interface binds; a reverse proxy or local proxy cannot turn a loopback listener into an unauthenticated endpoint.

## Public deployment requirements

The bundled listener is plain HTTP and does not require HTTPS for the authentication guard to operate. If it is exposed directly, provide `DSH_WEB_PASSWORD` through the service manager's environment file rather than a checked-in file. The default cookie configuration supports direct HTTP; an HTTPS deployment may set `secureCookie: true` in its Web auth configuration.

Authentication sessions live only in the service process and disappear on restart. The browser returns to `/auth/login` when it detects that its session is gone. A restart therefore requires users to sign in again.

## Useful checks

```sh
pnpm run test
pnpm run typecheck
pnpm run doc-sync
pnpm run lint
```

For the repeatable security patch and public-mode update procedure, see [`docs/patch.md`](docs/patch.md). For package-specific contracts, see [`packages/host/web-auth/README.md`](packages/host/web-auth/README.md) and [`packages/bundle/web-app/README.md`](packages/bundle/web-app/README.md). For the composition and extension model, see [`docs/architecture.md`](docs/architecture.md).

## License

[MIT](LICENSE)

Third-party dependencies and their licenses are disclosed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
