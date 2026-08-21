# @deepseek-ai/dsh-host-web-auth

[English](README.md) | 中文

面向 `dsh-host-webserver` 的宿主级登录认证插件。插件注册 `/auth/login`、`/auth/session` 与 `/auth/logout`，并在所有 HTTP route、SPA fallback 和 WebSocket upgrade 之前安装全局 guard；现有 route 插件不需要修改。`passwordEnv` 配置的是凭据引用，例如 `DSH_WEB_PASSWORD`；密码通过 `ctx.credentials` 解析，不会写进 cordis 配置。插件启用时如果该引用未配置，会在启动阶段失败，因此公网 Web 进程不会以不可用的登录边界启动。

会话使用不透明的随机 token，服务端只保存其 SHA-256 摘要，经过 `sessionTtlSeconds` 后过期，进程重启时全部失效。登录使用 CSRF 双提交 cookie，为 HTML 设置安全响应头，并将每个远端地址在 `loginAttemptWindowSeconds` 内的失败次数限制为 `loginAttemptLimit`。注销只接受携带 `X-DSH-CSRF` token 的 POST 请求。HTTPS 在前置代理终止时应启用 `secureCookie`；默认关闭，以便在可信局域网直接使用 HTTP IP 访问。

## 配置

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

Web bundle 对所有绑定地址都启用此插件，包括 `127.0.0.1`。反向代理可以把回环监听器公开到公网，因此不能根据绑定地址关闭认证。在公网绑定明文 HTTP 并不等于 TLS 部署；请使用 HTTPS 终止或私有网络，并确保代理后仍保留认证 guard。

## 模型体验

无，认证属于宿主传输层，不会产生提示词、工具、消息或 provider 请求。

#### KV Cache 影响

无；会话和凭据不会进入模型请求。

## 已知限制与后续工作

- 会话只保存在进程内，重启后全部失效。
- 本插件不提供 TLS；直接 HTTP 只适用于可信网络，公网部署需要 HTTPS 反向代理或 VPN。
- 登录限速只覆盖单进程和远端地址，分布式部署还需要上游限速器。
