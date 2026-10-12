import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { readFile } from "node:fs/promises";
import { WebSocketServer, type WebSocket } from "ws";
import { webRemoteControlClientToEndpointFrameSchema } from "@zcode/shared";
import {
  RelayPairingRegistry,
  type RelayAuthChallenge,
  type RelayLogger,
  type RelayPairEntry,
} from "./registry.js";

/**
 * ZCode 手机远控 relay（用户自托管）：HTTP 托管移动端页面 + WS `/ws` 配对与转发。
 *
 * - 零业务状态：重启即全部失效，桌面/手机按重连流程恢复；
 * - TLS 由前置（Caddy/traefik/cloudflared）终结，本服务只监听明文 WS；
 * - 端口/路径/上限/TTL/静态目录全部走环境变量。
 */

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
};

export interface RelayServerOptions {
  port: number;
  host: string;
  path: string;
  maxPhysicalFrameBytes: number;
  pairTtlMs: number;
  mobileDir: string | null;
  logger: RelayLogger;
  rateLimiter: {
    allowConnect(ip: string): boolean;
    allowFrame(ip: string): boolean;
  };
}

export interface RelayServerHandle {
  port: number;
  close(): Promise<void>;
}

export async function startRelayServer(options: RelayServerOptions): Promise<RelayServerHandle> {
  const registry = new RelayPairingRegistry({
    logger: options.logger,
    maxPhysicalFrameBytes: options.maxPhysicalFrameBytes,
    pairTtlMs: options.pairTtlMs,
    allowConnect: options.rateLimiter.allowConnect,
    allowFrame: options.rateLimiter.allowFrame,
  });
  const wss = new WebSocketServer({ noServer: true });
  const sweep = setInterval(() => registry.sweepExpired(), 60 * 60 * 1000);
  sweep.unref?.();

  const server: Server = createServer((req, res) => {
    // 修复说明：handleHttp 是 async，原先返回的 Promise 无人 catch；任何未预期异常都会变成
    // unhandledRejection，Node 24 默认直接退出进程（一个请求即可打挂 relay）。这里兜底回 500。
    handleHttp(req, res, options, registry).catch((error: unknown) => {
      options.logger.warn("relay: http handler failed", {
        message: error instanceof Error ? error.message : String(error),
      });
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      }
      res.end();
    });
  });
  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== options.path) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      void attachClient(ws, req.socket.remoteAddress ?? "unknown");
    });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(options.port, options.host, () => resolveListen());
  });
  const address = server.address();
  const port = address && typeof address === "object" ? address.port : options.port;
  options.logger.info("relay: listening", { port, path: options.path, host: options.host });

  return {
    port,
    async close() {
      clearInterval(sweep);
      for (const client of wss.clients) {
        client.close(1001, "relay-shutdown");
      }
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    },
  };

  async function attachClient(ws: WebSocket, ip: string): Promise<void> {
    // 修复说明：原实现在 auth_init（尚未校验 proof）时就给外层 entry/role 赋值，而 data /
    // pair_status_query 只检查 entry 是否存在，导致只要知道 device_sid、不发 auth_response
    // 也能向对端注入 data 帧、续期配对；device_unregister 更是完全不鉴权。
    // 现在把「待鉴权」与「已鉴权」分开：auth_init 只写 pending（含本 socket 独占的一次性挑战），
    // 只有 verifyProof 成功并 bindRole 后才写 authenticated；且每次使用前都要求 entry 上该角色
    // 绑定的仍是本 socket（与 lanEndpoint 的 entry.mobile === ws 判定一致），被互踢/被替换/
    // 配对被 drop 后自动失效。
    let pending: { entry: RelayPairEntry; challenge: RelayAuthChallenge } | undefined;
    let authenticated: { entry: RelayPairEntry; role: "device" | "mobile" } | undefined;
    if (!options.rateLimiter.allowConnect(ip)) {
      ws.close(4008, "rate-limited");
      return;
    }

    ws.on("message", (raw) => {
      if (!options.rateLimiter.allowFrame(ip)) {
        ws.close(4008, "rate-limited");
        return;
      }
      const text = typeof raw === "string" ? raw : raw.toString();
      if (Buffer.byteLength(text) > options.maxPhysicalFrameBytes) {
        options.logger.warn("relay: oversize frame dropped", {
          ip,
          bytes: Buffer.byteLength(text),
        });
        send(ws, { type: "error", code: "WRONG_PARAM", message: "frame too large" });
        ws.close(4009, "oversize");
        return;
      }
      let parsed: ReturnType<typeof webRemoteControlClientToEndpointFrameSchema.safeParse>;
      try {
        parsed = webRemoteControlClientToEndpointFrameSchema.safeParse(JSON.parse(text));
      } catch {
        send(ws, { type: "error", code: "WRONG_PARAM", message: "invalid json" });
        ws.close(4001, "WRONG_PARAM");
        return;
      }
      if (!parsed.success) {
        send(ws, { type: "error", code: "WRONG_PARAM", message: "invalid frame" });
        ws.close(4001, "WRONG_PARAM");
        return;
      }
      handleFrame(ws, ip, parsed.data).catch((error) => {
        options.logger.warn("relay: frame handling failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    });

    /** 本 socket 当前是否仍是某配对上该角色的已鉴权连接。 */
    function currentAuth(): { entry: RelayPairEntry; role: "device" | "mobile" } | undefined {
      if (!authenticated) return undefined;
      const { entry, role } = authenticated;
      const bound = role === "device" ? entry.device : entry.mobile;
      return bound === ws ? authenticated : undefined;
    }

    ws.on("close", () => {
      pending = undefined;
      if (!authenticated) return;
      const { entry } = authenticated;
      authenticated = undefined;
      const unbound = registry.unbind(entry, ws);
      if (unbound === "mobile" && entry.device) {
        // 通知桌面：手机已离开，回到 waiting。
        send(entry.device, { type: "pair_status_ack", pair_status: "waiting" });
      }
    });
    ws.on("error", () => ws.close(1011, "internal"));

    async function handleFrame(
      socket: WebSocket,
      clientIp: string,
      frame: Record<string, unknown>,
    ): Promise<void> {
      const type = frame.type;
      switch (type) {
        case "device_register_init": {
          const passHash = String(frame.pass_hash ?? "");
          if (!passHash) {
            fail(socket, "WRONG_PARAM");
            return;
          }
          const deviceSid = registry.register(passHash);
          send(socket, { type: "device_register_ack", device_sid: deviceSid });
          return;
        }
        case "auth_init": {
          // 一条 socket 只绑定一个身份；已鉴权后再发 auth_init 视为协议误用。
          if (authenticated) {
            fail(socket, "WRONG_PARAM");
            return;
          }
          const frameRole = frame.role === "mobile" ? "mobile" : "device";
          const deviceSid = String(frame.device_sid ?? "");
          const candidate = registry.lookup(deviceSid);
          if (!candidate) {
            fail(socket, "AUTH_FAILED");
            return;
          }
          // 只记录待鉴权状态；挑战按 socket 存放，不会覆盖其他连接的 nonce。
          pending = { entry: candidate, challenge: registry.issueChallenge(frameRole) };
          send(socket, { type: "auth_challenge", nonce: pending.challenge.value });
          return;
        }
        case "auth_response": {
          const attempt = pending;
          // 挑战一次性：无论成败都作废。
          pending = undefined;
          if (
            !attempt ||
            String(frame.device_sid ?? "") !== attempt.entry.deviceSid ||
            // 等待期间配对可能已被 drop / 过期，不再接受。
            registry.lookup(attempt.entry.deviceSid) !== attempt.entry ||
            !registry.verifyProof(attempt.entry, attempt.challenge, String(frame.proof ?? ""))
          ) {
            fail(socket, "AUTH_FAILED");
            return;
          }
          const { entry } = attempt;
          const role = attempt.challenge.role;
          registry.bindRole(entry, role, socket);
          authenticated = { entry, role };
          entry.pairStatus = role === "mobile" ? "matched" : entry.pairStatus;
          send(socket, {
            type: "auth_ack",
            pair_status: registry.pairStatusOf(entry),
          });
          if (role === "mobile" && entry.device) {
            send(entry.device, { type: "pair_status_ack", pair_status: "matched" });
          }
          options.logger.info("relay: authenticated", {
            role,
            clientIp,
            deviceSidSuffix: entry.deviceSid.slice(-6),
            pairStatus: registry.pairStatusOf(entry),
          });
          return;
        }
        case "pair_status_query": {
          const auth = currentAuth();
          if (!auth || String(frame.device_sid ?? "") !== auth.entry.deviceSid) {
            fail(socket, "AUTH_FAILED");
            return;
          }
          const { entry } = auth;
          registry.touch(entry);
          send(socket, { type: "pair_status_ack", pair_status: registry.pairStatusOf(entry) });
          return;
        }
        case "data": {
          const auth = currentAuth();
          if (!auth) {
            fail(socket, "AUTH_FAILED");
            return;
          }
          registry.touch(auth.entry);
          registry.forward(auth.role, auth.entry, frame.payload);
          return;
        }
        case "device_unregister": {
          // 桌面刷新配对/销毁：立即作废该 sid 的全部配对关系。
          // 只允许已鉴权的 device 注销自己的配对；mobile 或他人的 sid 一律拒绝。
          const auth = currentAuth();
          if (
            !auth ||
            auth.role !== "device" ||
            String(frame.device_sid ?? "") !== auth.entry.deviceSid
          ) {
            fail(socket, "AUTH_FAILED");
            return;
          }
          const target = auth.entry;
          authenticated = undefined;
          registry.drop(target);
          options.logger.info("relay: device unregistered", {
            deviceSidSuffix: target.deviceSid.slice(-6),
          });
          return;
        }
        default:
          fail(socket, "WRONG_PARAM");
      }
    }
  }
}

function send(ws: WebSocket, frame: unknown): void {
  if (ws.readyState !== ws.OPEN) return;
  ws.send(JSON.stringify(frame));
}

function fail(ws: WebSocket, code: "AUTH_FAILED" | "WRONG_PARAM" | "INTERNAL"): void {
  send(ws, { type: "error", code });
  ws.close(4001, code);
}

function isInsideRoot(root: string, target: string): boolean {
  return target.startsWith(root.endsWith(sep) ? root : root + sep);
}

async function handleHttp(
  req: IncomingMessage,
  res: ServerResponse,
  options: RelayServerOptions,
  registry: RelayPairingRegistry,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ status: "ok", ...registry.stats() }));
    return;
  }
  if (!options.mobileDir) {
    res.writeHead(503, { "content-type": "text/plain; charset=utf-8" });
    res.end(
      "Mobile app directory is not configured. Set ZCODE_RELAY_MOBILE_DIR to the built @zcode/web dist (contains mobile.html).\n",
    );
    return;
  }
  const root = resolve(options.mobileDir);
  const [rawPath = "/"] = url.pathname.split("?");
  const relative = rawPath === "/" ? "/mobile.html" : rawPath;
  // 修复说明：畸形百分号编码（如 `GET /%`）会让 decodeURIComponent 抛 URIError，
  // 原先未捕获，经未处理的 Promise 拒绝导致进程退出；按客户端错误回 400。
  let decoded: string;
  try {
    decoded = decodeURIComponent(relative);
  } catch {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end("Bad request\n");
    return;
  }
  const target = resolve(join(root, normalize(decoded)));
  // 修复说明：原 `startsWith(root)` 会放行同前缀的兄弟目录（root=/srv/web 时
  // /srv/web-secret 也匹配），改为要求以 root + 路径分隔符开头。
  if (!isInsideRoot(root, target)) {
    res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
    res.end("Forbidden\n");
    return;
  }
  try {
    const body = await readFile(target);
    res.writeHead(200, {
      "content-type": CONTENT_TYPES[extname(target).toLowerCase()] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    // SPA 回退：深链回 mobile.html。
    try {
      const fallback = await readFile(join(root, "mobile.html"));
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(fallback);
    } catch {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("Not found\n");
    }
  }
}
