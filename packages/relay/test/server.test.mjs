// relay 鉴权状态机与静态托管的端到端测试：真起 relay（127.0.0.1 随机端口），用 ws 客户端走 wire。
// server.ts 依赖 @zcode/shared 的 TS 源码，先用 esbuild 打成单文件再加载（与 build.mjs 同一工具链）。
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { request } from "node:http";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import WebSocket from "ws";

const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = join(packageDir, "dist", "test", "server.bundle.mjs");

const PASS_HASH = "test-pass-hash";

let relay;
let wsUrl;
let workDir;
const openSockets = new Set();

before(async () => {
  await build({
    entryPoints: [join(packageDir, "src", "server.ts")],
    outfile: bundlePath,
    bundle: true,
    platform: "node",
    target: "node24",
    format: "esm",
    external: ["ws"],
    logLevel: "silent",
  });
  const { startRelayServer } = await import(pathToFileURL(bundlePath).href);

  workDir = await mkdtemp(join(tmpdir(), "zcode-relay-test-"));
  const mobileDir = join(workDir, "web");
  await mkdir(mobileDir);
  await writeFile(join(mobileDir, "mobile.html"), "<!doctype html><title>mobile</title>");
  // 与静态根同前缀的兄弟目录：前缀匹配漏洞会把它当成根内文件返回。
  await mkdir(join(workDir, "web-secret"));
  await writeFile(join(workDir, "web-secret", "secret.txt"), "top-secret");

  const silent = { info() {}, warn() {} };
  relay = await startRelayServer({
    port: 0,
    host: "127.0.0.1",
    path: "/ws",
    maxPhysicalFrameBytes: 1024 * 1024,
    pairTtlMs: 60 * 60 * 1000,
    mobileDir,
    logger: silent,
    rateLimiter: { allowConnect: () => true, allowFrame: () => true },
  });
  wsUrl = `ws://127.0.0.1:${relay.port}/ws`;
});

after(async () => {
  for (const socket of openSockets) socket.terminate();
  await relay?.close();
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

/** 带帧队列的测试客户端：next() 取下一帧，closed 在关闭时 resolve。 */
async function connect() {
  const ws = new WebSocket(wsUrl);
  openSockets.add(ws);
  const queue = [];
  const waiters = [];
  let closeInfo;
  const closed = new Promise((resolveClosed) => {
    ws.on("close", (code) => {
      openSockets.delete(ws);
      closeInfo = { code };
      for (const waiter of waiters.splice(0)) waiter.reject(new Error(`closed ${code}`));
      resolveClosed(closeInfo);
    });
  });
  ws.on("message", (raw) => {
    const frame = JSON.parse(raw.toString());
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(frame);
    else queue.push(frame);
  });
  await new Promise((resolveOpen, rejectOpen) => {
    ws.once("open", resolveOpen);
    ws.once("error", rejectOpen);
  });
  return {
    ws,
    closed,
    send(frame) {
      ws.send(JSON.stringify(frame));
    },
    next(timeoutMs = 2000) {
      if (queue.length > 0) return Promise.resolve(queue.shift());
      if (closeInfo) return Promise.reject(new Error(`closed ${closeInfo.code}`));
      return new Promise((resolveNext, rejectNext) => {
        const timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          rejectNext(new Error("timed out waiting for frame"));
        }, timeoutMs);
        const waiter = {
          resolve: (frame) => {
            clearTimeout(timer);
            resolveNext(frame);
          },
          reject: (error) => {
            clearTimeout(timer);
            rejectNext(error);
          },
        };
        waiters.push(waiter);
      });
    },
    /** 断言在 ms 内没有收到任何帧。 */
    async expectSilence(ms = 200) {
      await new Promise((resolveWait) => setTimeout(resolveWait, ms));
      assert.deepEqual(queue, [], "unexpected frames received");
    },
  };
}

function proofFor(nonce, role, deviceSid) {
  return createHmac("sha256", PASS_HASH)
    .update(`${nonce}|${role}|${deviceSid}`)
    .digest("base64url");
}

function authInit(client, role, deviceSid) {
  client.send({ type: "auth_init", role, device_sid: deviceSid, client_ts: Date.now() });
}

async function authenticate(client, role, deviceSid) {
  authInit(client, role, deviceSid);
  const challenge = await client.next();
  assert.equal(challenge.type, "auth_challenge");
  client.send({
    type: "auth_response",
    device_sid: deviceSid,
    proof: proofFor(challenge.nonce, role, deviceSid),
    client_ts: Date.now(),
  });
  const ack = await client.next();
  assert.equal(ack.type, "auth_ack");
  return ack;
}

/** 注册设备并完成 device 鉴权；返回 { device, deviceSid }。 */
async function registerDevice() {
  const device = await connect();
  device.send({
    type: "device_register_init",
    device_mid: "test-machine",
    pass_hash: PASS_HASH,
    client_ts: Date.now(),
  });
  const registered = await device.next();
  assert.equal(registered.type, "device_register_ack");
  const deviceSid = registered.device_sid;
  const ack = await authenticate(device, "device", deviceSid);
  assert.equal(ack.pair_status, "waiting");
  return { device, deviceSid };
}

/** 设备 + 手机完成配对；返回 { device, mobile, deviceSid }。 */
async function pairDeviceAndMobile() {
  const { device, deviceSid } = await registerDevice();
  const mobile = await connect();
  const ack = await authenticate(mobile, "mobile", deviceSid);
  assert.equal(ack.pair_status, "matched");
  assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "matched" });
  return { device, mobile, deviceSid };
}

async function expectAuthFailedAndClosed(client) {
  assert.deepEqual(await client.next(), { type: "error", code: "AUTH_FAILED" });
  const { code } = await client.closed;
  assert.equal(code, 4001);
}

function rawGet(path) {
  return new Promise((resolveGet, rejectGet) => {
    // 用 host/port/path 选项原样发送路径（不经 URL 规范化），才能复现畸形百分号编码。
    const req = request({ host: "127.0.0.1", port: relay.port, path, method: "GET" }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () =>
        resolveGet({ status: res.statusCode, body: Buffer.concat(chunks).toString() }),
      );
    });
    req.on("error", rejectGet);
    req.setTimeout(2000, () => req.destroy(new Error("request timed out")));
    req.end();
  });
}

describe("relay 正常配对与转发", () => {
  test("设备注册 → 手机鉴权 matched → 双向 data 转发", async () => {
    const { device, mobile, deviceSid } = await pairDeviceAndMobile();

    mobile.send({ type: "data", payload: { hello: "from-mobile" } });
    assert.deepEqual(await device.next(), { type: "data", payload: { hello: "from-mobile" } });

    device.send({ type: "data", payload: { hello: "from-device" } });
    assert.deepEqual(await mobile.next(), { type: "data", payload: { hello: "from-device" } });

    device.send({ type: "pair_status_query", device_sid: deviceSid, client_ts: Date.now() });
    assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "matched" });
  });

  test("已鉴权 device 可注销自己的配对，旧 sid 随即失效", async () => {
    const { device, mobile, deviceSid } = await pairDeviceAndMobile();
    device.send({ type: "device_unregister", device_sid: deviceSid });
    await Promise.all([device.closed, mobile.closed]);

    const stale = await connect();
    authInit(stale, "mobile", deviceSid);
    await expectAuthFailedAndClosed(stale);
  });
});

describe("relay 鉴权状态机", () => {
  test("只发 auth_init、不完成 auth_response 时 data 被拒且不转发给对端", async () => {
    const { device, mobile, deviceSid } = await pairDeviceAndMobile();

    const attacker = await connect();
    authInit(attacker, "mobile", deviceSid);
    assert.equal((await attacker.next()).type, "auth_challenge");
    attacker.send({ type: "data", payload: { injected: true } });
    await expectAuthFailedAndClosed(attacker);

    await device.expectSilence();
    // 合法手机未被踢下线，链路仍可用。
    mobile.send({ type: "data", payload: { legit: true } });
    assert.deepEqual(await device.next(), { type: "data", payload: { legit: true } });
  });

  test("未鉴权连接直接发 data 被拒", async () => {
    const { device } = await pairDeviceAndMobile();
    const attacker = await connect();
    attacker.send({ type: "data", payload: { injected: true } });
    await expectAuthFailedAndClosed(attacker);
    await device.expectSilence();
  });

  test("未完成鉴权时 pair_status_query 被拒", async () => {
    const { deviceSid } = await registerDevice();

    const bare = await connect();
    bare.send({ type: "pair_status_query", device_sid: deviceSid, client_ts: Date.now() });
    await expectAuthFailedAndClosed(bare);

    const halfAuthed = await connect();
    authInit(halfAuthed, "device", deviceSid);
    assert.equal((await halfAuthed.next()).type, "auth_challenge");
    halfAuthed.send({ type: "pair_status_query", device_sid: deviceSid, client_ts: Date.now() });
    await expectAuthFailedAndClosed(halfAuthed);
  });

  test("未完成鉴权时 device_unregister 被拒，配对保持有效", async () => {
    const { device, deviceSid } = await registerDevice();

    const bare = await connect();
    bare.send({ type: "device_unregister", device_sid: deviceSid });
    await expectAuthFailedAndClosed(bare);

    const halfAuthed = await connect();
    authInit(halfAuthed, "device", deviceSid);
    assert.equal((await halfAuthed.next()).type, "auth_challenge");
    halfAuthed.send({ type: "device_unregister", device_sid: deviceSid });
    await expectAuthFailedAndClosed(halfAuthed);

    device.send({ type: "pair_status_query", device_sid: deviceSid, client_ts: Date.now() });
    assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "waiting" });
  });

  test("已鉴权 mobile 无法注销 device", async () => {
    const { device, mobile, deviceSid } = await pairDeviceAndMobile();
    mobile.send({ type: "device_unregister", device_sid: deviceSid });
    await expectAuthFailedAndClosed(mobile);

    // 手机断开后桌面回到 waiting，但配对本身仍在、桌面连接未被关闭。
    assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "waiting" });
    device.send({ type: "pair_status_query", device_sid: deviceSid, client_ts: Date.now() });
    assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "waiting" });
  });

  test("已鉴权 device 无法注销他人的 sid", async () => {
    const first = await registerDevice();
    const second = await registerDevice();
    second.device.send({ type: "device_unregister", device_sid: first.deviceSid });
    await expectAuthFailedAndClosed(second.device);

    first.device.send({
      type: "pair_status_query",
      device_sid: first.deviceSid,
      client_ts: Date.now(),
    });
    assert.deepEqual(await first.device.next(), {
      type: "pair_status_ack",
      pair_status: "waiting",
    });
  });

  test("其他连接的 auth_init 不会覆盖正在鉴权连接的挑战", async () => {
    const { device, deviceSid } = await registerDevice();
    const mobile = await connect();
    authInit(mobile, "mobile", deviceSid);
    const challenge = await mobile.next();
    assert.equal(challenge.type, "auth_challenge");

    const interloper = await connect();
    authInit(interloper, "mobile", deviceSid);
    assert.equal((await interloper.next()).type, "auth_challenge");

    mobile.send({
      type: "auth_response",
      device_sid: deviceSid,
      proof: proofFor(challenge.nonce, "mobile", deviceSid),
      client_ts: Date.now(),
    });
    assert.deepEqual(await mobile.next(), { type: "auth_ack", pair_status: "matched" });
    assert.deepEqual(await device.next(), { type: "pair_status_ack", pair_status: "matched" });
  });

  test("错误 proof 返回 AUTH_FAILED 并关闭", async () => {
    const { deviceSid } = await registerDevice();
    const mobile = await connect();
    authInit(mobile, "mobile", deviceSid);
    assert.equal((await mobile.next()).type, "auth_challenge");
    mobile.send({
      type: "auth_response",
      device_sid: deviceSid,
      proof: "wrong-proof",
      client_ts: Date.now(),
    });
    await expectAuthFailedAndClosed(mobile);
  });
});

describe("relay 静态托管", () => {
  test("畸形百分号编码返回 400，进程存活", async () => {
    const malformed = await rawGet("/%");
    assert.equal(malformed.status, 400);
    const malformedNested = await rawGet("/assets/%E0%A4%A.js");
    assert.equal(malformedNested.status, 400);

    const health = await rawGet("/healthz");
    assert.equal(health.status, 200);
    assert.equal(JSON.parse(health.body).status, "ok");
  });

  test("根路径返回 mobile.html", async () => {
    const page = await rawGet("/");
    assert.equal(page.status, 200);
    assert.match(page.body, /<title>mobile<\/title>/);
  });

  test("同前缀兄弟目录不可越界读取", async () => {
    for (const path of ["/..%2Fweb-secret%2Fsecret.txt", "/%2E%2E%5Cweb-secret%5Csecret.txt"]) {
      const escaped = await rawGet(path);
      assert.doesNotMatch(escaped.body, /top-secret/, path);
    }
  });
});
