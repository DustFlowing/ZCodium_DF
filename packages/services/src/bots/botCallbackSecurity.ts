import { randomBytes, timingSafeEqual } from "node:crypto";
import type { BotInboundMessage, BotProvider } from "@zcode/shared";

// Bots 入站回调与绑定的安全判定，规则见 .agents/specs/bots-callback-security.md。
// 这里只放不依赖 BotsService 运行时的判定逻辑；鉴权结论与失败计数仍由 BotsService 唯一持有。

export const BOT_WEBHOOK_DEFAULT_AUTH_HEADER = "x-zcode-bot-secret";
/** HTTP 层把入站请求头放进这个字段；它总是覆盖请求体里的同名字段。 */
export const BOT_WEBHOOK_HEADERS_PAYLOAD_KEY = "zcodeWebhookHeaders";

// 去掉易混的 0/1/I/O，剩 32 个字符，每字符正好 5 bit，便于手输。
export const BOT_BIND_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
// 13 × 5 = 65 bit，不低于 8 字节熵。
export const BOT_BIND_CODE_LENGTH = 13;

const BOT_BIND_MAX_FAILURES = 5;
const BOT_BIND_FAILURE_WINDOW_MS = 10 * 60_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * 常量时间比较 secret/token。任一侧缺失或为空、长度不同都直接判失败，
 * 避免 `===` 的提前返回把匹配前缀长度泄露给调用方。
 */
export function constantTimeEquals(
  expected: string | null | undefined,
  actual: string | null | undefined,
): boolean {
  if (!expected || !actual) {
    return false;
  }
  const expectedBytes = Buffer.from(expected, "utf8");
  const actualBytes = Buffer.from(actual, "utf8");
  if (expectedBytes.length !== actualBytes.length) {
    return false;
  }
  return timingSafeEqual(expectedBytes, actualBytes);
}

/**
 * 读取 webhook 入站 secret。只信任 HTTP 层附加的请求头：先取 Bot 配置的认证 Header，
 * 再回退默认 Header。请求体里的 webhookSecret 由发送方任意构造，不能作为凭据来源。
 */
export function readWebhookInboundSecret(
  payload: unknown,
  authHeaderName?: string,
): string | undefined {
  const headers = isRecord(payload) ? payload[BOT_WEBHOOK_HEADERS_PAYLOAD_KEY] : undefined;
  if (!isRecord(headers)) {
    return undefined;
  }
  const normalized = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      normalized.set(name.toLowerCase(), value);
    }
  }
  const customName = authHeaderName?.trim().toLowerCase();
  return (
    (customName ? normalized.get(customName) : undefined) ??
    normalized.get(BOT_WEBHOOK_DEFAULT_AUTH_HEADER)
  );
}

/**
 * 入站消息的 info 日志内容。info 在生产环境落盘，只保留定位所需的标识与长度，
 * 不得包含消息正文、displayName 等真实用户数据。
 */
export function formatInboundMessageLogSummary(
  provider: BotProvider,
  message: BotInboundMessage,
): string {
  return `provider callback provider=${provider} bot=${message.botId} user=${message.actor.providerUserId} messageId=${message.actor.providerMessageId ?? ""} textLength=${message.text.length} attachments=${message.attachments?.length ?? 0}`;
}

export function createBindCodeValue(random: (size: number) => Uint8Array = randomBytes): string {
  const bytes = random(BOT_BIND_CODE_LENGTH);
  let code = "";
  for (const byte of bytes) {
    // 字母表长度是 2 的幂，取低 5 bit 不会引入取模偏差。
    code += BOT_BIND_CODE_ALPHABET[byte & 31];
  }
  return code;
}

/** 绑定码匹配大小写不敏感，并容忍手输时夹带的空白与连字符。 */
export function normalizeBindCode(input: string): string {
  return input.replace(/[\s-]+/g, "").toUpperCase();
}

interface BindAttemptRecord {
  failures: number;
  windowStartedAt: number;
}

export interface BindAttemptLimiter {
  key(botId: string, providerUserId: string): string;
  /** 距离解除锁定的毫秒数；未锁定时为 0。 */
  retryAfterMs(key: string): number;
  recordFailure(key: string): void;
  reset(key: string): void;
  size(): number;
}

/**
 * 按 botId + providerUserId 统计 /bind 失败次数：自首次失败起的窗口内达到阈值后锁定到窗口结束。
 * 只存内存，与 bindCodes 同生命周期。
 */
export function createBindAttemptLimiter(
  options: { maxFailures?: number; windowMs?: number; now?: () => number } = {},
): BindAttemptLimiter {
  const maxFailures = options.maxFailures ?? BOT_BIND_MAX_FAILURES;
  const windowMs = options.windowMs ?? BOT_BIND_FAILURE_WINDOW_MS;
  const now = options.now ?? Date.now;
  const records = new Map<string, BindAttemptRecord>();

  function readActive(key: string, at: number): BindAttemptRecord | undefined {
    const record = records.get(key);
    if (record && at - record.windowStartedAt >= windowMs) {
      records.delete(key);
      return undefined;
    }
    return record;
  }

  return {
    key(botId, providerUserId) {
      // JSON 编码保证两段内容里出现分隔符时也不会拼出相同的 key。
      return JSON.stringify([botId, providerUserId]);
    },
    retryAfterMs(key) {
      const at = now();
      const record = readActive(key, at);
      if (!record || record.failures < maxFailures) {
        return 0;
      }
      return record.windowStartedAt + windowMs - at;
    },
    recordFailure(key) {
      const at = now();
      // 写入时顺带清理过期条目，避免大量一次性 providerUserId 让表无限增长。
      for (const [existingKey, record] of records) {
        if (at - record.windowStartedAt >= windowMs) {
          records.delete(existingKey);
        }
      }
      const record = records.get(key);
      if (record) {
        record.failures += 1;
      } else {
        records.set(key, { failures: 1, windowStartedAt: at });
      }
    },
    reset(key) {
      records.delete(key);
    },
    size() {
      return records.size;
    },
  };
}
