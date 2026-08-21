# 公网 Web 认证 patch

[English](patch.md) | 中文

本文档是带认证 Web 二开版本的更新清单，记录安全不变量、公网启动命令，以及拉取上游改动后需要重复执行的检查。

## 安全不变量

交付的 `web` profile 必须同时满足以下条件：

- `web-auth` 对所有绑定地址启用。`Host`、`Origin`、`trustedHosts` 或代理连接都不能证明用户身份。
- `webserver.requireGuard` 为 `true`。Web server 没有注册 guard 时必须 fail-closed，不能继续提供路由。
- 未认证访问 `/api/*` 返回 `401`；未认证的浏览器请求跳转到 `/auth/login`；未认证的 WebSocket upgrade 以 `401` 拒绝。
- 登录密码从 `DSH_WEB_PASSWORD` 凭据引用解析。该引用缺失时启动失败，不能启动一个未保护或不可登录的服务。
- 公网 Web 的权限默认值是 `read-only`，并要求操作审批。不要把私有 profile 的 `danger-full-access` 设置复制到公网 profile。
- 已认证 authority 的限制也覆盖文件系统发现与修改（`host.describe`、`host.listDirectory`、`host.createDirectory`）、会话导出和两条实时事件流 upgrade。它们即使是读取或物理下载／upgrade 路径，也不能匿名访问。
- 公网 bind 配置 `authenticatedHosts` 后，它会覆盖整个 `/api` transport，包括未来插件定义的 Remote endpoint；新安装的宿主 runner 不能悄悄绕过登录层。

这会关闭交付 Web profile 中的未认证访问路径，包括“回环监听器加代理公开”的情况。如果部署自己的 patch 禁用了 `web-auth`、设置了 `requireGuard: false`，或者有效会话／密码已经被窃取，则不属于这条默认访问路径；这些是部署覆盖或凭据失陷问题，不是 Host 头认证问题。

## 开启公网模式

在干净 checkout 中执行：

```sh
pnpm install
export DEEPSEEK_API_KEY='replace-with-a-rotated-key'
export DSH_WEB_PASSWORD='replace-with-a-long-random-password'
pnpm run build
pnpm dsh web --host 0.0.0.0 --port 3080
```

打开 `http://<server-ip>:3080/`，使用用户名 `admin` 和 `DSH_WEB_PASSWORD` 的值登录。Web profile 绑定 `127.0.0.1` 时也使用同一道认证 guard。

如果使用服务管理器，请把两个密钥放进它的环境配置中，不要写进 `cordis.yml`、shell 历史、日志或 Git。服务命令必须使用已构建的 checkout；需要公网监听时必须保留 `--host 0.0.0.0`。

## 更新后验证

启动服务前执行针对性检查：

```sh
pnpm run verify-cordis-config
pnpm exec vitest run \
  packages/bundle/web-app/tests/security-composition.spec.ts \
  packages/host/web-auth/tests/web-auth.spec.ts \
  packages/host/webserver/tests/webserver.spec.ts
pnpm run build
```

服务启动后，未认证请求必须继续被拒绝：

```sh
curl -i http://127.0.0.1:3080/api/settings.describe
curl -i http://127.0.0.1:3080/
```

第一个响应必须是 `401`。第二个响应必须跳转到 `/auth/login`，不能直接返回应用 shell。正常登录后，浏览器携带认证会话的 API 请求才可以返回 `2xx`。

## 拉取上游后重新应用

1. 使用 `git pull --ff-only`，检查 `packages/bundle/web-app/cordis.patch.yml` 和 `packages/host/web-auth/` 的冲突。
2. 保留 Web 行 `web-auth.enabled: true`、`webserver.requireGuard: true`、`sandbox-policy.mode: read-only` 和 `approval.policy: ask`。
3. 保留 `packages/host/web-auth/src/index.ts` 中的缺少密码即启动失败逻辑。
4. 执行针对性检查、`pnpm run typecheck` 和 `pnpm run doc-sync`。
5. 撤销并轮换本 patch 之前可能暴露的 key。不要把新值写入本文档。

不要把 `trustedHosts` 当作认证替代品。它用于浏览器来源和 DNS rebinding 防护，不能证明用户身份。
