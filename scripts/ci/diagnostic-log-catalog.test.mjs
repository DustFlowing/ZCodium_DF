// 防止诊断日志目录生成脚本因平台路径差异静默产出空目录。
import assert from "node:assert/strict";
import test from "node:test";
import { tsImport } from "tsx/esm/api";
import { collectDiagnosticLogCatalog, isCatalogSource } from "../diagnostic-log-catalog.mjs";
const committed = await tsImport(
  "../../packages/shared/src/diagnosticLogCatalog.ts",
  import.meta.url,
);
test("source filter accepts Windows and POSIX separators alike", () => {
  // 两种分隔符都用字面量覆盖，POSIX CI 也能发现 Windows 路径回归。
  for (const path of [
    "/repo/packages/shared/src/diagnosticPrivacy.ts",
    "C:\\repo\\packages\\shared\\src\\diagnosticPrivacy.ts",
    "C:\\repo\\apps\\zcode-cli\\packages\\core\\src\\nested\\index.tsx",
  ])
    assert.equal(isCatalogSource(path), true, path);
  for (const path of [
    "C:\\repo\\packages\\shared\\scripts\\build.ts",
    "C:\\repo\\packages\\shared\\src\\a.test.ts",
    "C:\\repo\\packages\\shared\\src\\a.spec.tsx",
    "C:\\repo\\packages\\shared\\src\\types.d.ts",
    "C:\\repo\\packages\\shared\\src\\diagnosticLogCatalog.ts",
    "C:\\repo\\packages\\shared\\src\\styles.css",
    "/repo/packages/shared/src/a.test.ts",
  ])
    assert.equal(isCatalogSource(path), false, path);
});
test("generator scans first-party sources and emits a non-empty, separator-free catalog", async () => {
  const catalog = await collectDiagnosticLogCatalog();
  // 路径过滤失效时只会剩下 4 条内置消息，前缀与模块为空。
  assert.ok(catalog.modules.length > 100, `modules: ${catalog.modules.length}`);
  assert.ok(catalog.messages.length > 100, `messages: ${catalog.messages.length}`);
  assert.ok(catalog.prefixes.length > 10, `prefixes: ${catalog.prefixes.length}`);
  assert.ok(catalog.modules.includes("packages/shared/src/diagnosticPrivacy.ts"));
  assert.ok(catalog.modules.some((path) => path.startsWith("apps/zcode-cli/packages/")));
  assert.ok(
    catalog.modules.every((path) => !path.includes("\\") && !/^(?:\/|[A-Za-z]:)/.test(path)),
  );
  assert.ok(!catalog.modules.includes("packages/shared/src/diagnosticLogCatalog.ts"));
  for (const text of [...catalog.messages, ...catalog.prefixes])
    assert.ok(!/https?:\/\//.test(text), text);
});
test("committed catalog is not an empty platform artifact", () => {
  assert.ok(committed.diagnosticModules.length > 100);
  assert.ok(committed.diagnosticMessages.length > 100);
  assert.ok(committed.diagnosticPrefixes.length > 10);
  assert.ok(committed.diagnosticModules.every((path) => !path.includes("\\")));
});
