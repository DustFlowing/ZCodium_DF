# Bots 回调与绑定的安全规则

> **状态：已实现。** 覆盖 `packages/services/src/bots` 的三项安全修复：Webhook 回调鉴权
> fail-closed、绑定码熵与失败限速、入站消息日志脱敏。

## 背景

复核 Bots 入站链路时确认了三项缺陷：

1. **Webhook 回调 fail-open。** `processProviderCallback` 只在 `bot.webhookSecretRef` 存在时才校验，
   且凭据读出为空时 `expectedSecret && expectedSecret !== inboundSecret` 直接放行。Webhook 的发送者身份
   `providerUserId` 完全来自请求体，因此未配置 secret 的 Bot 可以被任何能访问
   `/api/bots/webhook` 的人冒充已绑定用户驱动 Agent。同一处还有两个旁路：
   - 校验条件是 `bot.provider === "webhook"`，向 `/api/bots/webhook/<其他 provider 的 botId>` 发请求时
     整段校验被跳过；
   - `packages/server/src/http.ts` 把请求体整体展开后才覆盖 `webhookSecret`，没有 header 时请求体自带的
     `webhookSecret` 字段会被沿用。UI 指引只描述了请求头 `x-zcode-bot-secret`，请求体通道不是设计意图。
2. **绑定码过短且无失败限制。** `createCode` 用 `randomBytes(3)` 生成 6 位十六进制（24 bit），
   `handleBind` 不统计失败次数，可被枚举。
3. **用户消息原文拼进 info 日志。** `provider callback ... displayName=... text=...` 违反
   「不在日志中写入真实用户数据」。实际落盘前还有一层 sink 脱敏（`safeLogArgs`，见
   `packages/shared/src/diagnosticPrivacy.ts`）：模板字符串只保留日志目录登记过的固定前缀，
   插值写成 `[omitted]`，所以原文此前并未真正写出。调用点仍需修正，不能把隐私边界只押在 sink 上。

## 范围

### 纳入

- Webhook provider 的入站鉴权规则与 HTTP 状态。
- 飞书/Lark verification token 比较改为常量时间。
- 绑定码格式、匹配规则、失败限速。
- Bots 目录下 info/warn/error 级别日志的用户数据边界。

### 排除

- Web 后端监听地址、Origin 校验、限速、CSP 等其他复核项。
- 飞书/Lark 的 fail-closed：飞书只走 `Lark.WSClient` 长连接，`http.ts` 对非 webhook provider 的 HTTP
  回调直接返回 400，入站事件的来源由长连接的 app 凭据保证；verification token 是可选的附加校验，
  保持「配置了才校验」的现有语义。
- 绑定码 TTL（`BOT_BIND_CODE_TTL_MS`）与 UI 流程。

## 状态所有者

| 状态                  | 所有者                                           | 说明                                                                |
| --------------------- | ------------------------------------------------ | ------------------------------------------------------------------- |
| Webhook secret        | credential store（`BotConfig.webhookSecretRef`） | 只由 `BotsService.saveBot` 写入；回调路径只读                       |
| 认证 Header 名        | `BotConfig.webhookAuthHeaderName`                | 缺省为 `x-zcode-bot-secret`                                         |
| 入站请求头            | `packages/server` HTTP 层（每请求）              | 以 `zcodeWebhookHeaders` 传给 `BotsService`，始终覆盖请求体同名字段 |
| 鉴权判定              | `BotsService.processProviderCallback`            | 唯一判定点；HTTP 层不比较 secret，只透传状态码                      |
| 绑定码（`bindCodes`） | `BotsService`（内存）                            | 进程重启即失效                                                      |
| 绑定失败计数          | `BotsService`（内存，`bindAttemptLimiter`）      | key = `botId` + `providerUserId`，与 `bindCodes` 同生命周期         |

纯函数（常量时间比较、请求头取值、绑定码生成/归一化、限速器）集中在
`packages/services/src/bots/botCallbackSecurity.ts`，不持有跨请求状态以外的事实，由 `BotsService` 调用。

## 规则

### R1 Webhook 回调鉴权（fail-closed）

对 `provider === "webhook"` 的回调，在解析消息、执行任何 provider 钩子之前判定，以下任一成立即拒绝：

- 请求指向的 Bot 不存在，或其 `provider` 不是 `webhook`；
- Bot 没有 `webhookSecretRef`；
- 凭据读取失败或读出为空；
- 请求头中没有 secret，或与期望值不相等。

拒绝时返回 `{ ok: false, replies: [], status: 401, responseBody: { ok: false, error } }`，HTTP 层回 401。
所有拒绝原因使用同一响应体，不向调用方区分「Bot 不存在」「未配置 secret」「secret 错误」；
具体原因只写入 warn 日志（不含 secret 与请求体）。

入站 secret 只从请求头读取：先取 Bot 配置的 `webhookAuthHeaderName`，再回退 `x-zcode-bot-secret`
（Header 名大小写不敏感）。请求体中的 `webhookSecret`、`zcodeWebhookHeaders` 字段不被信任。

### R2 常量时间比较

Webhook secret 与飞书 verification token 都用 `crypto.timingSafeEqual` 比较 UTF-8 字节；
长度不同或任一侧缺失直接判失败。

### R3 绑定码

- 13 个字符，字母表 `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`（去掉易混的 `0/1/I/O`），每字符 5 bit，
  共 65 bit 熵，由 `crypto.randomBytes` 生成。
- 匹配前归一化：去掉首尾及中间的空白与 `-`，转大写。大小写不敏感。

### R4 绑定失败限速

- 按 `botId + providerUserId` 计数。绑定码不存在、已过期或不属于该 Bot 都计一次失败。
- 自首次失败起 10 分钟窗口内累计 5 次失败后进入锁定：窗口结束前的 `/bind` 一律回复
  `bindTooManyAttempts`，**包括绑定码正确的请求**，且不再消耗绑定码。
- 窗口结束后计数清零；绑定成功立即清零。非私聊的 `/bind` 不计数（先于限速返回 `bindPrivateOnly`）。
- 计数只在内存中，过期条目在写入时清理。

### R5 日志

- info/warn/error 级别不得包含消息正文、`displayName`、secret、token 或请求体。
- 入站消息的 info 日志只记录 `provider / bot / user / messageId / textLength / attachments`
  （`formatInboundMessageLogSummary`）。
- 不新增带原文的 debug 日志：sink 对 debug 同样没有隐私例外（`DIAGNOSTICS.md`），原文不会被写出。
- 新增或修改日志前缀后同步 `packages/shared/src/diagnosticLogCatalog.ts`，否则整行会被写成 `[omitted]`。

## 事件顺序

```text
外部系统 ──POST /api/bots/webhook[/:botId]──▶ HTTP 层（packages/server）
                                               │ 解析 JSON；附加 zcodeWebhookHeaders（覆盖请求体同名字段）
                                               ▼
                                   BotsService.processProviderCallback
                                               │ ① findCallbackBot
                                               │ ② R1 鉴权：bot 是 webhook？secret 已配置且非空？
                                               │           请求头 secret 常量时间相等？
                                   ┌── 否 ─────┤
                                   ▼           │ 是
                         401 + 统一响应体      ▼
                         （warn 记录原因）   ③ parseCallback → 幂等去重 → handleInboundMessage
                                               │        /bind ─▶ handleBind
                                               │                  │ R4 已锁定？──是──▶ bindTooManyAttempts
                                               │                  │ 绑定码有效？──否──▶ 失败计数 +1，bindCodeInvalid
                                               │                  ▼ 是
                                               │                写入 BotConfig，删除绑定码，清零计数
                                               ▼
                                     200 / 503（既有语义不变）
```

## 兼容性

- 设置向导中 Webhook Bot 的连通性测试本来就要求已配置 secret（`webhookProvider.test`），
  因此按向导创建的 Bot 不受影响。手工写配置且没有 secret 的 Webhook Bot 会开始收到 401，需补上 secret。
- 只在请求体里带 `webhookSecret`、不带请求头的调用方会收到 401，需改为请求头。
- 绑定码变长，UI 只展示并复制 `/bind <code>`（`break-all`），不对长度做假设；AstrBot 桥接把
  `/bind` 文本原样转发，同样不受影响。

## 验收场景

| #   | 场景                                                            | 期望                                                    |
| --- | --------------------------------------------------------------- | ------------------------------------------------------- |
| 1   | Webhook Bot 未配置 secret，收到回调                             | 401，不产生回复，不触达 `handleInboundMessage`          |
| 2   | Webhook Bot 的凭据读出为空                                      | 401                                                     |
| 3   | secret 错误，或只在请求体里带 `webhookSecret`                   | 401                                                     |
| 4   | 请求头 `x-zcode-bot-secret` 正确                                | 通过，进入命令处理                                      |
| 5   | Bot 配置了自定义 `webhookAuthHeaderName`，用该请求头携带 secret | 通过                                                    |
| 6   | 回调的 `botId` 指向非 webhook Bot 或不存在的 Bot                | 401                                                     |
| 7   | 生成绑定码                                                      | 13 位、仅含规定字母表、多次生成互不相同                 |
| 8   | 用小写或带 `-` 的绑定码绑定                                     | 成功                                                    |
| 9   | 同一用户连续 5 次错误绑定码后再用正确绑定码                     | 回复 `bindTooManyAttempts`，Bot 未被绑定                |
| 10  | 锁定窗口结束后                                                  | 计数清零，可再次尝试                                    |
| 11  | 入站消息被处理                                                  | info 日志含 `textLength`，不含正文与 `displayName`      |
| 12  | 回调被拒绝或被处理后检查 sink 输出                              | 只出现登记过的固定前缀，不含正文、`displayName`、secret |

测试入口：`pnpm --filter @zcode/services test`（`node --import tsx --test`）。
