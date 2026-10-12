import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";
import type { BotConfig, BotProviderCallbackResult } from "@zcode/shared";
import { BOT_BIND_CODE_LENGTH } from "../src/bots/botCallbackSecurity.js";
import { createBotsService } from "../src/bots/botsService.js";
import { createDefaultBotCommands } from "../src/bots/config.js";
import { BotsRepo } from "../src/bots/repo.js";
import { setDataBaseDir } from "../src/paths.js";

type BotsServiceDeps = Parameters<typeof createBotsService>[0];

const SECRET = "test-only-webhook-secret";
const INVALID_SECRET_TEXT = "Webhook secret 校验失败。";

function createBot(overrides: Partial<BotConfig> & Pick<BotConfig, "id" | "provider">): BotConfig {
  return {
    name: overrides.id,
    enabled: true,
    allowedWorkspaces: ["*"],
    allowedCommands: createDefaultBotCommands(),
    currentOptions: {},
    replyMode: "assistant_changes",
    ...overrides,
  };
}

const bots: BotConfig[] = [
  createBot({ id: "hook-ok", provider: "webhook", webhookSecretRef: "cred-ok" }),
  createBot({ id: "hook-no-secret", provider: "webhook" }),
  createBot({ id: "hook-empty-secret", provider: "webhook", webhookSecretRef: "cred-empty" }),
  createBot({
    id: "hook-custom-header",
    provider: "webhook",
    webhookSecretRef: "cred-ok",
    webhookAuthHeaderName: "X-Custom-Auth",
  }),
  createBot({ id: "hook-bind", provider: "webhook", webhookSecretRef: "cred-ok" }),
  createBot({ id: "tg-bot", provider: "telegram", credentialRef: "cred-tg" }),
];

let dataDir = "";
let service: ReturnType<typeof createBotsService>;
let messageSeq = 0;

before(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "zcode-bots-callback-security-"));
  setDataBaseDir(dataDir);
  await new BotsRepo().writeConfig({ version: 3, bots });
  const credentials = new Map<string, string>([
    ["cred-ok", SECRET],
    ["cred-empty", ""],
  ]);
  service = createBotsService({
    credentialService: {
      load: async (key: string) => credentials.get(key) ?? null,
      save: async (key: string, value: string) => void credentials.set(key, value),
      delete: async (key: string) => void credentials.delete(key),
    } as BotsServiceDeps["credentialService"],
    // 这些场景在鉴权或 /bind 阶段就结束，不会触达任务与模型服务。
    zcodeTaskService: {} as BotsServiceDeps["zcodeTaskService"],
    modelSelectionService: {} as BotsServiceDeps["modelSelectionService"],
    runStartupBackgroundTasks: false,
  });
});

after(async () => {
  await service.disposeAllAndWait();
  setDataBaseDir(null);
  await rm(dataDir, { recursive: true, force: true });
});

function callback(
  botId: string,
  options: {
    headers?: Record<string, string>;
    text?: string;
    userId?: string;
    extra?: Record<string, unknown>;
  } = {},
): Promise<BotProviderCallbackResult> {
  messageSeq += 1;
  return service.handleProviderCallbackResponse("webhook", {
    userId: options.userId ?? "user-1",
    text: options.text ?? "/help",
    chatType: "private",
    messageId: `message-${messageSeq}`,
    ...options.extra,
    botId,
    zcodeWebhookHeaders: options.headers ?? {},
  });
}

function assertRejected(result: BotProviderCallbackResult): void {
  assert.equal(result.status, 401);
  assert.equal(result.ok, false);
  assert.deepEqual(result.replies, []);
  assert.deepEqual(result.responseBody, { ok: false, error: INVALID_SECRET_TEXT });
}

test("未配置 secret 的 webhook Bot 拒绝回调（401）", async () => {
  assertRejected(await callback("hook-no-secret"));
  assertRejected(await callback("hook-no-secret", { headers: { "x-zcode-bot-secret": "" } }));
  assertRejected(await callback("hook-no-secret", { headers: { "x-zcode-bot-secret": SECRET } }));
});

test("凭据读出为空时拒绝回调（401）", async () => {
  assertRejected(await callback("hook-empty-secret"));
  assertRejected(await callback("hook-empty-secret", { headers: { "x-zcode-bot-secret": "" } }));
});

test("secret 缺失或错误时拒绝回调（401）", async () => {
  assertRejected(await callback("hook-ok"));
  assertRejected(await callback("hook-ok", { headers: { "x-zcode-bot-secret": "wrong" } }));
  assertRejected(
    await callback("hook-ok", { headers: { "x-zcode-bot-secret": `${SECRET}-suffix` } }),
  );
});

test("请求体自带的 webhookSecret 不被信任", async () => {
  assertRejected(await callback("hook-ok", { extra: { webhookSecret: SECRET } }));
});

test("指向非 webhook Bot 或不存在的 Bot 时拒绝回调（401）", async () => {
  assertRejected(await callback("tg-bot", { headers: { "x-zcode-bot-secret": SECRET } }));
  assertRejected(await callback("missing-bot", { headers: { "x-zcode-bot-secret": SECRET } }));
});

test("secret 正确时通过并进入命令处理", async () => {
  const result = await callback("hook-ok", { headers: { "x-zcode-bot-secret": SECRET } });
  assert.notEqual(result.status, 401);
  assert.equal(result.ok, true);
  assert.equal(result.replies.length, 1);
  // 未绑定用户得到的是业务层回复，说明已越过鉴权。
  assert.match(result.replies[0]!.text, /未启用/);
});

test("自定义认证 Header 携带正确 secret 时通过", async () => {
  const result = await callback("hook-custom-header", { headers: { "x-custom-auth": SECRET } });
  assert.notEqual(result.status, 401);
  assert.equal(result.replies.length, 1);
});

test("绑定码连续失败触发锁定，正确绑定码也被拒绝", async () => {
  const headers = { "x-zcode-bot-secret": SECRET };
  const { code } = await service.createBindCode({ botId: "hook-bind", ttlMs: 60_000 });
  assert.equal(code.length, BOT_BIND_CODE_LENGTH);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = await callback("hook-bind", {
      headers,
      userId: "attacker",
      text: `/bind WRONG${attempt}`,
    });
    assert.match(result.replies[0]!.text, /绑定码无效或已过期/);
  }
  const locked = await callback("hook-bind", {
    headers,
    userId: "attacker",
    text: `/bind ${code}`,
  });
  assert.match(locked.replies[0]!.text, /尝试次数过多/);
  const afterLock = (await service.getConfig()).bots.find((bot) => bot.id === "hook-bind");
  assert.equal(afterLock?.providerUserId, undefined);

  // 锁定按 botId + providerUserId 计，其他用户仍可用同一绑定码（小写、带连字符）绑定。
  const formatted = `${code.slice(0, 4)}-${code.slice(4)}`.toLowerCase();
  const bound = await callback("hook-bind", {
    headers,
    userId: "owner",
    text: `/bind ${formatted}`,
  });
  assert.match(bound.replies[0]!.text, /绑定成功/);
  const afterBind = (await service.getConfig()).bots.find((bot) => bot.id === "hook-bind");
  assert.equal(afterBind?.providerUserId, "owner");
});

test("落盘日志不含消息原文、displayName 与 secret", async () => {
  const text = "TOP-SECRET-BODY-42 请勿落盘";
  const displayName = "Display-Name-Should-Not-Leak";
  const captured: string[] = [];
  const original = { log: console.log, warn: console.warn, error: console.error };
  const capture = (...args: unknown[]): void => void captured.push(args.map(String).join(" "));
  console.log = capture;
  console.warn = capture;
  console.error = capture;
  try {
    await callback("hook-ok", {
      headers: { "x-zcode-bot-secret": SECRET },
      text,
      extra: { displayName },
    });
    // 被拒绝的请求也不能把请求体或 secret 写进日志。
    await callback("hook-ok", {
      headers: { "x-zcode-bot-secret": "wrong-secret-value" },
      text,
      extra: { displayName },
    });
  } finally {
    Object.assign(console, original);
  }
  const output = captured.join("\n");
  // sink 只放行日志目录里登记过的固定前缀；两条前缀都出现说明目录已同步。
  assert.match(output, /provider callback provider=/);
  assert.match(output, /webhook callback rejected bot=/);
  assert.equal(output.includes("TOP-SECRET-BODY-42"), false);
  assert.equal(output.includes(displayName), false);
  assert.equal(output.includes(SECRET), false);
  assert.equal(output.includes("wrong-secret-value"), false);
});
