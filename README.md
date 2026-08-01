# SillyTavern SSO Sidecar

**语言：** 简体中文 | [English](README.en.md)

一个部署在 Authentik 代理 outpost 与 SillyTavern 之间的 fail-closed 反向
代理。它将稳定的 Authentik UID 映射到 SillyTavern handle，安全地预配账户、
同步管理员组成员身份，并为兼容 OpenAI 的 LLM API 提供范围严格受限、使用
服务身份验证的中继。

![](https://img.shields.io/badge/python-3.12-blue) ![](https://img.shields.io/badge/deps-aiohttp-green) [![](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE) [![](https://github.com/YatsukiRenka/sso-sidecar/actions/workflows/test.yml/badge.svg)](https://github.com/YatsukiRenka/sso-sidecar/actions/workflows/test.yml)

## 安全模型

Sidecar 将浏览器流量和 SillyTavern 服务端的 LLM 流量视为两条独立的信任路径：

```text
Browser -> Authentik outpost -> sidecar /... -> SillyTavern
                                  ^
SillyTavern server ---------------+-- /v1 -> upstream LLM API
                                      relay token   real API key
```

- 普通 SillyTavern 请求只接受来自 `TRUSTED_PROXY_CIDRS` 所列地址的连接，
  并且必须同时包含 `X-Authentik-Uid` 和 `X-Authentik-Username`。
  身份信息缺失或来源不受信任时，请求会被拒绝。
- Sidecar 不会转发 SillyTavern 原生的密码登录/找回、密码修改以及本地用户管理
  端点。Authentik 始终是身份与角色的唯一事实来源。SillyTavern 后端也必须位于
  私有网络中。
- 预配过程使用受密码保护的 SillyTavern 管理员账户登录。新建的纯 SSO 用户会
  获得一个确定性生成的高熵密码，该密码绝不会返回给浏览器。
- 带签名的绑定 Cookie 会将 SillyTavern 的长期浏览器会话与稳定的 Authentik
  UID 绑定。绑定缺失或不匹配时，Sidecar 会丢弃旧的后端 Cookie，直到
  SillyTavern 为当前 SSO 身份签发会话 Cookie。这样可以防止浏览器切换用户后
  复用上一位用户的 SillyTavern 会话。
- UID 映射保存在 Sidecar 自己的状态文件中，并通过原子替换更新。
  SillyTavern 的 `_storage`、`settings.json` 和 `secrets.json` 绝不会被
  直接修改。每个 `STATE_FILE` 只能运行一个 Sidecar 副本；进程内锁无法协调
  多个并发副本。
- `/v1` 只接受 `GET /v1/models`、`POST /v1/chat/completions` 和
  `POST /v1/completions`。它要求使用独立的 Bearer 中继令牌，对严格的 JSON
  对象和允许列表中的模型进行校验与规范化，拒绝查询参数，移除客户端 Cookie
  与身份请求头，然后注入真实的上游密钥。模型端点根据 `ALLOWED_MODELS`
  在本地生成，因此不会泄露上游模型目录。
- SillyTavern 从服务端发起中继请求，不会携带原始用户身份。因此受管账户共享
  `API_PROXY_TOKEN`，Sidecar 无法归因单次中继使用，也无法只吊销某一个用户。
  请在上游供应商处设置速率与费用限制；若令牌可能泄露，请轮换令牌。

Authentik 文档说明，代理组使用竖线分隔（`foo|bar|baz`），Sidecar 也按此格式
解析。参见
[Authentik 代理请求头参考](https://docs.goauthentik.io/add-secure-apps/providers/proxy/#headers-sent-to-upstream-applications)。

## SillyTavern 必需配置

请在 SillyTavern 的 `config.yaml` 中配置多用户模式、网络白名单和原生
Authentik SSO。以下设置与后文 Compose 示例中的固定 Sidecar 地址一致：

```yaml
whitelistMode: true
whitelist:
  - ::1
  - 127.0.0.1
  - 172.30.0.20 # 允许 sidecar 连接 SillyTavern

# 当 Authentik 服务的用户地址并非全部列在上方时，建议使用此设置。
# 改为 true 前请先阅读下方说明。
enableForwardedWhitelist: false

enableUserAccounts: true
allowKeysExposure: false

sso:
  autheliaAuth: false
  authentikAuth: true
  trustedProxies:
    - 172.30.0.20 # sidecar 地址，而不是 Authentik outpost 地址
```

Sidecar 地址必须同时出现在 `whitelist` 和 `sso.trustedProxies` 中，但二者
用途不同：前者允许 Sidecar 建立网络连接，后者允许它提供规范化后的 Authentik
身份请求头。默认的 `whitelistDockerHosts: true` 只会加入 Docker 宿主机与
网关地址，不会加入同级 Sidecar 容器的地址。

SillyTavern 1.18.0 默认将 `enableForwardedWhitelist` 设为 `true`。Sidecar
会保留转发的客户端 IP 请求头，因此该设置会要求 Sidecar 地址和每个被转发的
客户端地址**同时**匹配 `whitelist`。只有确实需要按客户端 IP 设置允许列表时
才应保持启用，并添加所有获准的客户端 IP 或范围尽量收窄的 CIDR。若私有
SillyTavern 后端应接受所有经 Authentik 身份验证并通过 Sidecar 的用户，请按
上例设为 `false`，同时确保无法通过其他路径访问后端网络。

请保持 `sso.autheliaAuth` 关闭。Sidecar 提供规范化后的
`X-Authentik-Username` 身份；启用 Authelia 会额外引入一条基于
`Remote-User` 的身份路径。Sidecar 会剥离替代身份请求头作为纵深防御，但未使用
的认证模式仍应保持关闭。

`allowKeysExposure: false` 同样是必需设置。受管用户会把中继凭据保存为
SillyTavern 的 `api_key_custom`；启用密钥暴露后，该共享凭据可能通过密钥查看或
用户备份功能泄露。

面向浏览器的账户路由允许列表已按 SillyTavern commit
[`8172dcd0ee67`](https://github.com/SillyTavern/SillyTavern/commit/8172dcd0ee67)
完成审计。部署其他 release、fork 或 staging 构建前，请重新核对这些路由。

[SillyTavern SSO 文档](https://docs.sillytavern.app/administration/sso/)
说明了受信任代理的要求。

此外：

1. 为 `ADMIN_HANDLE` 指定的 SillyTavern 账户设置强密码。绝不能让该管理员
   账户没有密码。
2. 保持 SillyTavern 端口私有，只有 Sidecar 可以访问它。
3. 为 Authentik outpost 和 Sidecar 分配稳定的私有地址（或稳定且范围尽量
   收窄的 CIDR），并在 `TRUSTED_PROXY_CIDRS` 中配置 outpost 地址。

这些控制项有意作用于不同的网络跃点：

| 设置 | 允许的行为 |
|---|---|
| Sidecar `TRUSTED_PROXY_CIDRS` | Authentik outpost 的源地址提供身份信息 |
| SillyTavern `whitelist` | Sidecar 的源地址建立连接；`enableForwardedWhitelist: true` 时还包括被转发的客户端 |
| SillyTavern `sso.trustedProxies` | Sidecar 的源地址提供 SSO 身份信息 |

## 配置

### SSO 与账户预配

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ST_BACKEND` | `http://sillytavern:8000` | 私有 SillyTavern URL |
| `LISTEN_PORT` | `8001` | Sidecar 监听端口 |
| `LOG_LEVEL` | `INFO` | 标准 Python 日志级别名称 |
| `ADMIN_HANDLE` | `admin` | 受密码保护、用于预配的 SillyTavern 管理员账户 |
| `ADMIN_PASSWORD` / `_FILE` | 必填 | 管理员密码；至少 20 个字符 |
| `USER_PASSWORD_SECRET` / `_FILE` | 必填 | 用于派生受管用户密码的稳定密钥；至少 32 个字符 |
| `ADMIN_GROUPS` | `admins,staff` | 授予 SillyTavern 管理员权限的 Authentik 组，以逗号分隔；留空表示不允许任何 SSO 管理员 |
| `AUTO_PROVISION` | `true` | 通过管理员 API 创建缺失的映射账户 |
| `ALLOW_USERNAME_LINKING` | `false` | 允许 username 匹配的用户认领尚未绑定的已有 handle |
| `TRUSTED_PROXY_CIDRS` | 无 | 必填；以逗号分隔的 Authentik outpost 源 CIDR |
| `STATE_FILE` | `/var/lib/sso-sidecar/mappings.json` | Sidecar 自有的原子 UID 映射文件 |
| `ST_DATA_DIR` | `/st-data/data` | 可选的只读旧版数据根目录，用于导入旧 `ssoUid` 映射 |
| `UID_CACHE_TTL` | `300` | 成功的映射/角色缓存生存时间，单位为秒 |
| `SSO_MAX_BODY_BYTES` | `524288000` | 解码后的 SillyTavern 请求最大大小；请求体采用流式传输而非整体缓冲 |
| `SSO_BINDING_COOKIE_SECURE` | `true` | 为 UID 绑定 Cookie 设置 Secure；仅在本地纯 HTTP 测试时禁用 |

`ALLOW_USERNAME_LINKING=false` 可防止他人通过复用 username 接管已有的
SillyTavern 账户。旧 `ssoUid` 记录会以只读方式导入，不需要启用此开关。
如需有意执行一次性迁移来绑定尚未绑定的账户，请仅在目标用户登录期间启用此
开关；验证状态文件后，再次将其禁用。

身份缓存刷新时，Sidecar 会根据 `ADMIN_GROUPS` 对账管理员角色。因此，如果某个
SSO 绑定账户的 Authentik 组不匹配此设置，对该账户的手工提权会被撤销；带外
管理请使用独立的 `ADMIN_HANDLE` 账户。

### LLM 中继

| 变量 | 默认值 | 说明 |
|---|---|---|
| `API_PROXY_ENABLED` | `true` | 启用范围受限的 `/v1` 中继和默认用户配置 |
| `API_BASE_URL` | 占位值 | 上游 OpenAI 兼容基础 URL，通常以 `/v1` 结尾 |
| `API_KEY` / `_FILE` | 必填 | 真实的上游 API 密钥；绝不会写入用户数据 |
| `API_PROXY_TOKEN` / `_FILE` | 必填 | 独立的随机 Bearer 中继令牌；至少 32 个字符 |
| `ALLOWED_MODELS` | `deepseek-v4-flash` | 有顺序、以逗号分隔的模型允许列表 |
| `DEFAULT_MODEL` | 允许列表中的第一个模型 | 也必须出现在 `ALLOWED_MODELS` 中 |
| `ST_API_BASE` | `http://sso-sidecar:8001/v1` | 写入受管用户自定义 API 设置的内部 URL |
| `API_MAX_BODY_BYTES` | `10485760` | 中继 JSON 请求体的最大大小 |

SillyTavern 容器必须能够访问 `ST_API_BASE`。不要将它指向受 Authentik
保护的公共浏览器 URL：SillyTavern 会从服务端发起自定义 API 请求。Sidecar
会通过 SillyTavern 自身的已认证密钥 API，将 `API_PROXY_TOKEN`（而非真实
API 密钥）写入受管用户的 `api_key_custom` 密钥。

每个密钥都支持 Docker/Kubernetes 风格的文件变量。例如，可以设置
`API_KEY_FILE=/run/secrets/api_key`，而不是 `API_KEY`。同一个密钥同时设置
两种形式会被拒绝。

可使用以下命令为各项生成彼此独立的随机值：

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

启动时要求四个不同信任域的密钥彼此独立：如果上游密钥、中继令牌、管理员
密码或受管用户派生密钥之间存在复用，Sidecar 会拒绝启动。

## Compose 示例

以下示例假设 Authentik outpost 地址为 `172.30.0.10`，Sidecar 地址为
`172.30.0.20`，且 SillyTavern 和 outpost 都加入了同一个私有网络。不要直接
发布 Sidecar 或 SillyTavern 的端口。

```yaml
services:
  sso-sidecar:
    build: ./sso-sidecar
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    environment:
      ST_BACKEND: http://sillytavern:8000
      ADMIN_HANDLE: admin
      ADMIN_PASSWORD_FILE: /run/secrets/st_admin_password
      USER_PASSWORD_SECRET_FILE: /run/secrets/user_password_secret
      ADMIN_GROUPS: admins,staff
      TRUSTED_PROXY_CIDRS: 172.30.0.10/32
      STATE_FILE: /var/lib/sso-sidecar/mappings.json
      ST_DATA_DIR: /st-data/data
      API_PROXY_ENABLED: "true"
      API_BASE_URL: https://your-llm-provider.example/v1
      API_KEY_FILE: /run/secrets/upstream_api_key
      API_PROXY_TOKEN_FILE: /run/secrets/api_proxy_token
      ALLOWED_MODELS: deepseek-v4-flash
      DEFAULT_MODEL: deepseek-v4-flash
      ST_API_BASE: http://sso-sidecar:8001/v1
    secrets:
      - st_admin_password
      - user_password_secret
      - upstream_api_key
      - api_proxy_token
    volumes:
      - sillytavern_data:/st-data/data:ro
      - sidecar_state:/var/lib/sso-sidecar
    networks:
      sso_internal:
        ipv4_address: 172.30.0.20

networks:
  sso_internal:
    external: true

volumes:
  sillytavern_data:
    external: true
  sidecar_state:

secrets:
  st_admin_password:
    file: ./secrets/st_admin_password
  user_password_secret:
    file: ./secrets/user_password_secret
  upstream_api_key:
    file: ./secrets/upstream_api_key
  api_proxy_token:
    file: ./secrets/api_proxy_token
```

### Linux 宿主机权限

运行镜像会在依赖安装完成后移除 `pip`，并将 `/app/app.py` 设置为 root 所有、
权限为 `0444`。运行用户只能写入状态目录。

镜像以 UID/GID `10001:10001` 运行。建议使用示例中的 `sidecar_state` 命名
卷，因为它不会用任意宿主机目录覆盖镜像中已正确设置所有者的状态目录。如果
改用 `./sidecar-state:/var/lib/sso-sidecar` 之类的绑定挂载，请在启动前为
容器用户创建源目录：

```sh
sudo install -d -o 10001 -g 10001 -m 0700 ./sidecar-state
```

任何已有的 `mappings.json` 也必须允许 UID 10001 读写。Sidecar 会在同一目录
中创建临时文件，再以原子方式替换 `mappings.json`，因此仅让该文件本身可写
并不足够。

Docker Compose 会将顶层 `secrets.<name>.file` 源实现为绑定挂载。因此，容器
用户必须能够遍历每一级父目录，而且每个密钥文件都必须允许 UID 或 GID 10001
读取。针对本例中四个文件的一种最小权限配置如下：

```sh
sudo chown root:10001 ./secrets ./secrets/*
sudo chmod 0750 ./secrets
sudo chmod 0440 ./secrets/*
```

不要在顶层密钥定义中放置 `mode`：该字段接受的是 `file` 等源类型，而不是
挂载权限。服务级长语法虽然包含 `uid`、`gid` 和 `mode` 字段，但对于 `file`
源，Docker Compose 会因使用绑定挂载而忽略这些字段。请改为设置宿主机文件的
权限；[Compose 服务密钥参考](https://docs.docker.com/reference/compose-file/services/#secrets)
记录了这一限制。

上述命令假设使用未启用用户命名空间重映射的 Linux Docker Engine。Rootless
Docker、用户命名空间和 Docker Desktop 可能采用不同方式转换所有权；请验证
运行中的容器能够读取每个已配置的 `*_FILE`，并写入 `STATE_FILE` 所在目录。

将 Authentik 代理提供程序的内部主机指向 `http://sso-sidecar:8001`。同时请
确保网络仍允许 Sidecar 访问已配置的 LLM 提供商；也可以为其连接单独的出口
网络。

## 更新

以下步骤假设使用上面的源码构建 Compose 示例，代码检出路径为
`./sso-sidecar`，服务名为 `sso-sidecar`。如果实际部署不同，请相应替换路径或
服务名。

### 更新前

1. 记录当前部署的修订版本，以便需要时重新构建并回滚：

   ```sh
   git -C ./sso-sidecar rev-parse HEAD
   ```

2. 在原容器仍然存在时备份身份映射：

   ```sh
   install -d -m 0700 ./backup
   docker compose cp \
     sso-sidecar:/var/lib/sso-sidecar/mappings.json \
     ./backup/mappings.json.pre-upgrade
   ```

   如果尚未生成映射文件，可以跳过复制。备份中不含账户密码，但包含稳定身份
   映射，仍应妥善保管。

3. 保留现有 `sidecar_state` 卷和全部已配置密钥。尤其不能随意更换
   `USER_PASSWORD_SECRET`，否则 Sidecar 将无法验证已有受管账户。更新过程中
   不要运行 `docker compose down --volumes`。

4. 对照[必需的 SillyTavern 配置](#sillytavern-必需配置)和当前环境变量表检查
   部署。从 [`cf99d6f`](https://github.com/YatsukiRenka/sso-sidecar/commit/cf99d6f26257d759ed4d03d627ebad02478e9921)
   之前的版本升级时，请确保已设置 `allowKeysExposure: false` 和
   `sso.autheliaAuth: false`。现在，整数、布尔值、日志级别、URL 或密钥文件配置
   无效时会在启动阶段清晰地失败，不再被隐式接受。

### 重建并替换 Sidecar

在包含 Compose 文件的目录中运行：

```sh
git -C ./sso-sidecar switch main
git -C ./sso-sidecar pull --ff-only origin main
docker compose config --quiet
docker compose build --pull sso-sidecar
docker compose up --detach --no-deps --wait sso-sidecar
docker compose logs --tail=100 sso-sidecar
```

如果修改了 SillyTavern 的必需设置，请先按照现有部署方式重启或重新创建
SillyTavern，再测试 SSO。单独运行 `docker compose restart` 不会应用发生变化的
镜像或环境变量，因此上面的流程使用 `up`。

确认服务健康后，依次测试普通用户 SSO 登录、适用时的管理员组用户登录以及已
配置的 LLM 中继。`cf99d6f` 引入的更新没有改变映射状态格式，无需手工迁移
状态。

### 回滚

检出更新前记录的修订版本，重新构建镜像，并只重新创建 Sidecar：

```sh
git -C ./sso-sidecar switch --detach <previous-revision>
docker compose build sso-sidecar
docker compose up --detach --no-deps --wait sso-sidecar
docker compose logs --tail=100 sso-sidecar
```

不要删除状态卷。本次更新不要求恢复映射备份，应将其保留为恢复副本。如果未来
版本明确更改了状态格式，请遵循该版本的迁移说明，并且只在 Sidecar 停止时恢复
对应备份，同时保持 UID/GID 为 `10001:10001`。准备再次尝试升级时，运行
`git -C ./sso-sidecar switch main`。

## 映射与故障行为

- 状态文件中已有的 UID 始终映射到同一个 handle，即使 Authentik username 发生
  变化，或新 username 无法转换为 ASCII handle 也是如此。
- 一个 UID 不能重新绑定到另一个 handle，一个 handle 也不能绑定到多个 UID。
- 预配或存储失败会返回 `503`，并在后续请求中重试。绝不会退回到直接传递
  原始 Authentik username 的方式。
- 从所有已配置管理员组中移除用户后，会在下一次未命中缓存的角色检查中降级
  其映射账户；将用户加入任一管理员组则会提升权限。
- 每次未命中缓存的同步都会验证受管账户的凭据；账户被删除后重新创建或密码
  发生更改时，会在同步角色前拒绝继续。创建/配置序列中断后，处于待处理状态
  的账户也可以恢复。请保持 `USER_PASSWORD_SECRET` 稳定，以便持续验证。
- 受管用户的 API 配置带有指纹。轮换 `API_PROXY_TOKEN`、更改
  `DEFAULT_MODEL` 或更改 `ST_API_BASE` 后，会在该用户下一次未命中缓存的
  登录时重新应用设置与中继密钥。
- 每个 `STATE_FILE` 只能运行一个 Sidecar 副本。水平扩展的副本需要使用独立
  状态文件或外部事务性状态存储。

## 开发

安装开发依赖并执行回归测试套件：

```sh
python -m pip install -r requirements-dev.txt
ruff check app.py tests
ruff format --check app.py tests
python -m unittest discover -s tests -v
python -m py_compile app.py
```

测试套件覆盖中继身份验证与路由限制、编码路径遍历、有界分块请求体、替代身份
请求头移除、严格 JSON 与模型校验、有界流式及压缩 SSO 请求体、受信任代理
强制检查、原始 Cookie 保真、重定向改写、账户路由默认拒绝、按 UID 并发预配、
清晰的启动错误、经过凭据验证的重试、不可变 UID 绑定、状态迁移、旧版记录
健壮性以及 Authentik 组解析。

## 许可证

[AGPL-3.0](LICENSE)，Copyright (C) 2026 YatsukiRenka。

本项目是一个用户通过网络访问的反向代理，因此选用 AGPL-3.0 而非 GPL-3.0：
任何人修改本项目并将其作为网络服务提供给用户，即使从不分发二进制，也必须向
这些用户提供对应的完整源码。SillyTavern 本身同为 AGPL-3.0。
