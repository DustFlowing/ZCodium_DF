import assert from "node:assert/strict";
import test from "node:test";
import {
  BOT_BIND_CODE_ALPHABET,
  BOT_BIND_CODE_LENGTH,
  BOT_WEBHOOK_HEADERS_PAYLOAD_KEY,
  constantTimeEquals,
  createBindAttemptLimiter,
  createBindCodeValue,
  formatInboundMessageLogSummary,
  normalizeBindCode,
  readWebhookInboundSecret,
} from "../src/bots/botCallbackSecurity.js";

test("constantTimeEquals 只在两侧非空且完全相等时通过", () => {
  assert.equal(constantTimeEquals("s3cret", "s3cret"), true);
  assert.equal(constantTimeEquals("s3cret", "s3creT"), false);
  assert.equal(constantTimeEquals("s3cret", "s3cret-longer"), false);
  assert.equal(constantTimeEquals("s3cret", undefined), false);
  assert.equal(constantTimeEquals(null, undefined), false);
  assert.equal(constantTimeEquals("", ""), false);
  assert.equal(constantTimeEquals("密钥", "密钥"), true);
});

test("readWebhookInboundSecret 只信任 HTTP 层附加的请求头", () => {
  const headers = { "x-zcode-bot-secret": "from-header", "x-custom-auth": "from-custom" };
  assert.equal(
    readWebhookInboundSecret({ [BOT_WEBHOOK_HEADERS_PAYLOAD_KEY]: headers }),
    "from-header",
  );
  assert.equal(
    readWebhookInboundSecret({ [BOT_WEBHOOK_HEADERS_PAYLOAD_KEY]: headers }, "X-Custom-Auth"),
    "from-custom",
  );
  // 自定义 Header 缺失时回退默认 Header。
  assert.equal(
    readWebhookInboundSecret(
      { [BOT_WEBHOOK_HEADERS_PAYLOAD_KEY]: { "X-ZCode-Bot-Secret": "mixed-case" } },
      "x-missing",
    ),
    "mixed-case",
  );
  // 请求体自带的 webhookSecret 不是可信来源。
  assert.equal(readWebhookInboundSecret({ webhookSecret: "from-body" }), undefined);
  assert.equal(readWebhookInboundSecret("not-an-object"), undefined);
  assert.equal(
    readWebhookInboundSecret({ [BOT_WEBHOOK_HEADERS_PAYLOAD_KEY]: { "x-zcode-bot-secret": 1 } }),
    undefined,
  );
});

test("入站消息的 info 日志只含标识与长度，不含原文和 displayName", () => {
  const text = "TOP-SECRET-BODY-42 请勿落盘";
  const summary = formatInboundMessageLogSummary("webhook", {
    botId: "bot-1",
    text,
    attachments: [{ id: "a", kind: "file", filename: "private-name.txt", mimeType: "text/plain" }],
    actor: {
      provider: "webhook",
      botId: "bot-1",
      providerUserId: "user-1",
      providerMessageId: "message-1",
      displayName: "Display-Name-Should-Not-Leak",
      chatType: "private",
    },
  });
  assert.equal(
    summary,
    `provider callback provider=webhook bot=bot-1 user=user-1 messageId=message-1 textLength=${text.length} attachments=1`,
  );
});

test("绑定码长度、字母表与熵符合要求", () => {
  // 13 个字符 × 5 bit = 65 bit，不低于 8 字节熵。
  assert.equal(BOT_BIND_CODE_ALPHABET.length, 32);
  assert.ok(BOT_BIND_CODE_LENGTH * 5 >= 64);
  for (const confusing of ["0", "1", "I", "O"]) {
    assert.equal(BOT_BIND_CODE_ALPHABET.includes(confusing), false);
  }
  const codes = new Set<string>();
  for (let index = 0; index < 500; index += 1) {
    const code = createBindCodeValue();
    assert.equal(code.length, BOT_BIND_CODE_LENGTH);
    for (const char of code) {
      assert.ok(BOT_BIND_CODE_ALPHABET.includes(char), `unexpected char ${char}`);
    }
    assert.equal(normalizeBindCode(code), code);
    codes.add(code);
  }
  assert.equal(codes.size, 500);
});

test("createBindCodeValue 用到随机源的每个字节", () => {
  const code = createBindCodeValue((size) => Buffer.alloc(size, 0xff));
  assert.equal(code, BOT_BIND_CODE_ALPHABET[31]!.repeat(BOT_BIND_CODE_LENGTH));
});

test("normalizeBindCode 大小写不敏感并忽略空白与连字符", () => {
  assert.equal(normalizeBindCode("  abcd-efgh 2345k \n"), "ABCDEFGH2345K");
});

test("绑定失败限速：窗口内超过阈值锁定，窗口结束后清零", () => {
  let now = 1_000_000;
  const limiter = createBindAttemptLimiter({ maxFailures: 5, windowMs: 600_000, now: () => now });
  const key = limiter.key("bot-1", "user-1");
  for (let attempt = 0; attempt < 4; attempt += 1) {
    limiter.recordFailure(key);
    assert.equal(limiter.retryAfterMs(key), 0);
    now += 1_000;
  }
  limiter.recordFailure(key);
  // 窗口从首次失败起算，此时已过去 4 秒。
  assert.equal(limiter.retryAfterMs(key), 596_000);
  // 其他用户、其他 Bot 互不影响。
  assert.equal(limiter.retryAfterMs(limiter.key("bot-1", "user-2")), 0);
  assert.equal(limiter.retryAfterMs(limiter.key("bot-2", "user-1")), 0);
  now += 595_999;
  assert.equal(limiter.retryAfterMs(key), 1);
  now += 1;
  assert.equal(limiter.retryAfterMs(key), 0);
  limiter.recordFailure(key);
  assert.equal(limiter.retryAfterMs(key), 0);
});

test("绑定失败限速：成功后清零，过期条目被清理", () => {
  let now = 0;
  const limiter = createBindAttemptLimiter({ maxFailures: 2, windowMs: 1_000, now: () => now });
  const key = limiter.key("bot", "user");
  limiter.recordFailure(key);
  limiter.reset(key);
  limiter.recordFailure(key);
  assert.equal(limiter.retryAfterMs(key), 0);
  limiter.recordFailure(key);
  assert.equal(limiter.retryAfterMs(key), 1_000);
  assert.equal(limiter.size(), 1);
  now = 5_000;
  limiter.recordFailure(limiter.key("bot", "other"));
  assert.equal(limiter.size(), 1);
});

test("限速 key 不会因分隔符拼接而碰撞", () => {
  const limiter = createBindAttemptLimiter();
  assert.notEqual(limiter.key("a", "b::c"), limiter.key("a::b", "c"));
});
