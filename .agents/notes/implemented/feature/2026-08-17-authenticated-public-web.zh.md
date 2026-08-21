# Agent Note: 公网 Web 登录认证

Status: implemented

[English](2026-08-17-authenticated-public-web.md) | 中文

## 问题

Web profile 可以绑定所有接口，但其浏览器信任检查不是用户认证。没有登录机制时公开该 profile 会使全部路由可达；如果认证只保护页面，特权设置与凭据方法仍被限制在回环地址。通过 IP 使用明文 HTTP 的部署还会触发安全上下文以外不可用的浏览器 API；重复打开登录页可能使表单中的 CSRF token 失效；宿主重启后，一直打开的页面会报告插件加载失败，而不是要求用户重新登录。

## 决策

Web 组合对所有绑定地址都挂载 host web-auth 包作为全局 WebServer guard。它通过凭据服务解析配置的密码；引用缺失时启动失败；只保存经过哈希的进程内会话 token，以稳定的双提交 CSRF cookie 和按地址统计的尝试次数限制保护登录，并在分发前守卫 HTTP 路由与 WebSocket upgrade。绑定地址不决定是否认证，因此反向代理不能把未认证的回环监听器公开出去。

Web bundle 将 base 的权限行替换为只读文件效果与操作审批。需要更宽权限的部署必须选择独立的私有 profile，或显式添加后续 patch。

未认证登录页复用 Web 应用的字体、明暗模式配色、焦点状态和 DeepSeek Harness 品牌样式。CSS 内嵌在页面中，CSP 仅允许这段内嵌样式；认证前不加载脚本、字体、图片或其他外部资源。

客户端连接把服务权威信任与已认证权限分开。trustedHosts 继续针对 Host、Origin、Fetch-Metadata 与 WebSocket 请求防御跨站访问和 DNS rebinding。authenticatedHosts 默认为空；它只为已经通过更早认证层的 authority 放行文件系统读写、会话导出、事件流 upgrade 和固定特权方法。它非空时还会覆盖完整的 `/api` transport，包括未来插件定义的 Remote endpoint，避免宿主 runner 意外成为匿名执行面。每个条目还必须存在于 trustedHosts。全接口 Web 运行时在全局登录 guard 之后提供其已认证的服务权威，回环访问继续通过既有回环规则获得权限。

浏览器可见的 UUID 创建使用共享 random-uuid 包；其 RFC 4122 version 4 实现依赖 crypto.getRandomValues()，不使用仅限安全上下文的 crypto.randomUUID()。登录路由会在重复 GET 请求中复用已有 CSRF cookie。外部客户端 bundle 加载失败时，模块 loader 会探测 /auth/session；明确返回未认证时，页面带着当前路径跳转登录，其余失败仍保留插件诊断。

## 验证

包测试覆盖 WebServer guard 生命周期、真实 Loader 组合与登录、CSRF 复用、登录限速、已认证权威子集校验、特权方法准入、HTTP 可用的 UUID 消费方、会话失效后的跳转，以及登录页安全响应头和品牌卡片标记。Web 组合包测试覆盖全接口与回环组合。VPS 构建部署验证：未登录设置访问返回 401，登录后会话为已认证状态，agent preset 客户端 bundle 返回 JavaScript 并注册模块，已认证的 settings.describe 返回成功 RPC 响应。

## 备选方案

**把 trustedHosts 当作认证。** 不予采纳，因为权威 allowlist 可以阻止 rebinding，却不能证明用户身份；用它准入特权方法会把可达性悄悄变成授权。

**让特权方法继续只允许回环访问。** 不予采纳，因为已认证的公网部署会显示设置 UI，但所有请求都会以 HTTP 403 失败。

**把密码或会话保存在 Cordis 配置中。** 不予采纳，因为配置不是凭据存储，持久 bearer token 还会扩大泄露与重放窗口。凭据提供方和进程内会话使两种值都不会进入配置与会话日志。

**允许未登录访问所有静态资源。** 不予采纳，因为这会建立第二条未认证的应用交付路径，也不能恢复进程重启前一直打开的页面。只有真实脚本加载失败且会话端点明确返回未认证时，页面才会跳转。

## 后果

全接口 Web profile 在页面、插件 bundle、API 与 WebSocket 传输上共享同一道登录边界。自定义远程组合只有在显式组合更早的认证 guard 与匹配的 authenticatedHosts 子集时，才能开放特权 API。会话在重启后丢失且不跨进程共享；一直打开的页面会返回登录。直接暴露公网的明文 HTTP 仍不提供传输机密性，因此生产部署需要 HTTPS 终止或可信私有网络。
