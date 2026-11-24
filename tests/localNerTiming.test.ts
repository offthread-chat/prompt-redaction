import assert from "node:assert/strict";
import test from "node:test";
import { buildLocalNerTiming } from "../src/lib/localNerTiming.ts";

const resource = (name: string, startTime: number, duration: number, transferSize = 100, decodedBodySize = 1000) =>
  ({ name, startTime, duration, transferSize, decodedBodySize });
const summarize = (entries: ReturnType<typeof resource>[]) => buildLocalNerTiming({
  entries, started: 100, ended: 1000, weightsLoadMs: 500,
  outcome: "ready", runtimeOrigin: "https://offthread.chat",
});

test("separates weights, runtime resource loading, and total readiness without leaking URLs", () => {
  const timing = summarize([
    resource("https://huggingface.co/repo/resolve/rev/model.quant.onnx?token=secret", 120, 450),
    resource("https://offthread.chat/ort/v1/ort-wasm-simd-threaded.asyncify.mjs", 200, 50),
    resource("https://offthread.chat/ort/v1/ort-wasm-simd-threaded.asyncify.wasm", 240, 300),
    resource("https://offthread.chat/private", 100, 800),
    resource("https://offthread.chat/ort/v1/ort-wasm-simd-threaded.wasm", 1, 10000),
  ]);
  assert.deepEqual(timing, {
    outcome: "ready", total_load_ms: 900, weights_load_ms: 500,
    weights_fetch_ms: 450, weights_cache: "network",
    runtime_fetch_ms: 340, runtime_cache: "network",
  });
  assert.ok(!JSON.stringify(timing).includes("secret"));
});

test("missing or timing-restricted weights are unknown, never assumed to be cached", () => {
  assert.equal(summarize([]).weights_fetch_ms, null);
  assert.equal(summarize([]).weights_cache, "unknown");
  assert.equal(summarize([
    resource("https://huggingface.co/model.quant.onnx", 100, 200, 0, 0),
  ]).weights_cache, "unknown");
});

test("identifies observable HTTP cache hits and keeps incomplete loads nullable", () => {
  const entries = [resource("https://offthread.chat/ort/v1/ort-wasm-simd-threaded.wasm", 100, 2, 0)];
  assert.equal(summarize(entries).runtime_cache, "http_cache");
  const failed = buildLocalNerTiming({ entries: [], started: 10, ended: 20,
    weightsLoadMs: null, outcome: "error", runtimeOrigin: "https://offthread.chat" });
  assert.equal(failed.outcome, "error");
  assert.equal(failed.weights_load_ms, null);
  assert.equal(failed.runtime_fetch_ms, null);
});
