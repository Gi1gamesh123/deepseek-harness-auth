# Agent Note: Authenticated public Web access

Status: implemented

English | [中文](2026-08-17-authenticated-public-web.zh.md)

## Problem

The Web profile can bind all interfaces, but its browser trust checks are not user authentication. Exposing that profile without a login made every route reachable, while applying authentication only to the page left privileged settings and credential methods pinned to loopback. Plain-HTTP IP deployments also exercised browser APIs unavailable outside secure contexts, repeated login-page loads could invalidate the form's CSRF token, and a Host restart left an open page reporting a plugin-load failure instead of asking the user to sign in again.

## Decision

The Web composition mounts the host web-auth package as a global WebServer guard for every bind address. It resolves the configured password through the credentials service and fails boot when the reference is missing, stores only hashed in-memory session tokens, protects login with a stable double-submit CSRF cookie and per-address attempt limits, and guards HTTP routes and WebSocket upgrades before dispatch. Bind address is not an authentication decision, so a reverse proxy cannot expose an unauthenticated loopback listener.

The Web bundle replaces the base permission rows with read-only file effects and approval prompts. Deployments that need broader access must choose a separate private profile or explicit later patch.

The client connection separates serving-authority trust from authenticated privilege. trustedHosts continues to defend Host, Origin, Fetch-Metadata, and WebSocket requests against cross-site and DNS-rebinding access. authenticatedHosts defaults to empty; it admits filesystem reads/writes, session exports, event-stream upgrades, and fixed privileged methods only for authorities whose requests already passed an earlier authentication layer. When non-empty it also gates the complete `/api` transport, including future plugin-defined Remote endpoints, so a host runner cannot become an accidental anonymous execution surface. Each entry must also exist in trustedHosts. The all-interfaces Web runtime supplies its authenticated serving authorities after the global login guard, while loopback remains privileged through its existing loopback rule.

Browser-visible UUID creation uses the shared random-uuid package, whose RFC 4122 version 4 implementation relies on crypto.getRandomValues() rather than secure-context-only crypto.randomUUID(). The login route reuses an existing CSRF cookie across repeated GET requests. When an external client bundle fails to load, the module loader probes /auth/session; an explicit unauthenticated result redirects to login with the current path, while other failures retain the plugin diagnostic.

## Verification

Package tests cover the WebServer guard lifecycle, real Loader composition and login, CSRF reuse, login throttling, authenticated-host subset validation, privileged-method admission, HTTP-safe UUID consumers, and expired-session redirect. The Web bundle tests cover all-interfaces versus loopback composition. The built VPS deployment verifies unauthenticated settings access returns 401, login returns an authenticated session, the agent-preset client bundle returns JavaScript and registers its module, and authenticated settings.describe returns a successful RPC response.

## Alternatives considered

**Treat trustedHosts as authentication.** Rejected because an authority allowlist prevents rebinding but proves no user identity; using it for privileged methods would silently convert reachability into authorization.

**Keep privileged methods loopback-only.** Rejected because an authenticated public deployment then presents settings UI that always fails with HTTP 403.

**Store the password or sessions in Cordis configuration.** Rejected because configuration is not a credential store and durable bearer tokens expand the disclosure and replay window. The credential provider and process-local sessions keep both values out of configuration and session logs.

**Allow every static asset without a session.** Rejected because it creates a second unauthenticated application delivery path and does not recover an already-open page after a process restart. The session probe redirects only after a real script failure and an explicit unauthenticated response.

## Consequences

An all-interfaces Web profile has one login boundary across the page, plugin bundles, API, and WebSocket transports. Privileged APIs remain unavailable to custom remote compositions unless they explicitly combine an earlier authentication guard with a matching authenticatedHosts subset. Sessions are lost on restart and are not shared across processes; open pages recover by returning to login. Direct public HTTP still lacks transport confidentiality, so production exposure requires HTTPS termination or a trusted private network.
