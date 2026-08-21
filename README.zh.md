# DeepSeek Harness Auth

[English](README.md) | 中文

本仓库是 DeepSeek Harness 的二开版本，面向自托管 Web 部署。它增加了公网绑定和账号密码认证，同时保留基于 Cordis 的插件架构。

这是一个只提供源码的开发仓库。这个二开版本没有预构建 npm 包，每次部署前都需要在本地安装依赖并完成编译。

## 本仓库增加的功能

- Web profile 对所有绑定地址都启用主机认证插件；绑定到 `0.0.0.0` 不会绕过认证。
- 登录保护覆盖 Web UI、API 路由、SPA 回退和 WebSocket 升级。
- 浏览器端使用兼容 Linux 的 UUID 回退；服务重启导致会话失效时自动回到登录页。
- 登录使用 CSRF 双提交 Cookie、进程内存会话和失败登录限流。
- 密码从 `DSH_WEB_PASSWORD` 读取；凭据、Cookie 和会话令牌不会提交到仓库。

## 环境要求

- Node.js `22.19` 或更高版本，以及 `pnpm`。
- 模型请求需要 `DEEPSEEK_API_KEY`。
- 为 `DSH_WEB_PASSWORD` 准备一个足够长的随机值。

<a id="run"></a><a id="run-from-source"></a>

## 编译和运行

克隆本仓库，并在本地编译运行时和浏览器资源：

```sh
git clone https://github.com/Gi1gamesh123/deepseek-harness-auth.git
cd deepseek-harness-auth
pnpm install
export DEEPSEEK_API_KEY='your-deepseek-api-key'
export DSH_WEB_PASSWORD='choose-a-long-random-password'
pnpm run build
pnpm dsh web --host 0.0.0.0 --port 3080
```

打开 `http://<server-ip>:3080/`，使用用户名 `admin` 和 `DSH_WEB_PASSWORD` 的值登录。Web profile 在回环和全接口绑定上都要求登录；反向代理或本地代理不能把回环监听器变成未认证端点。

## 公网部署要求

内置监听器使用明文 HTTP，认证 guard 本身不要求 HTTPS 才能工作。直接暴露时，`DSH_WEB_PASSWORD` 应通过服务管理器的环境文件提供，不要写入代码仓库。默认 Cookie 配置兼容直接使用 HTTP；使用 HTTPS 部署时可以在 Web auth 配置中设置 `secureCookie: true`。

认证会话只保存在服务进程内存中，服务重启后会全部失效。浏览器检测到会话消失时会回到 `/auth/login`，因此重启后用户需要重新登录。

## 常用检查

```sh
pnpm run test
pnpm run typecheck
pnpm run doc-sync
pnpm run lint
```

可重复执行的安全 patch 和公网模式更新流程见 [`docs/patch.md`](docs/patch.md)。包级契约见 [`packages/host/web-auth/README.md`](packages/host/web-auth/README.md) 和 [`packages/bundle/web-app/README.md`](packages/bundle/web-app/README.md)。组合方式和扩展模型见 [`docs/architecture.md`](docs/architecture.md)。

## 许可证

[MIT](LICENSE)

第三方依赖及其许可证见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
