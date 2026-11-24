/** Resource Timing is also available inside the detector's worker. */
type ResourceTiming = Pick<PerformanceResourceTiming,
  "name" | "startTime" | "duration" | "transferSize" | "decodedBodySize"
>;

export function summarizeNerResource(entries: ResourceTiming[], matches: (url: URL) => boolean) {
  const resources = entries.filter((entry) => {
    try { return matches(new URL(entry.name)); } catch { return false; }
  });
  if (!resources.length) return { fetch_ms: null, cache: "unknown" } as const;
  // Zero sizes can mean cross-origin timing restrictions, not a cache hit.
  const cache = resources.some((entry) => entry.transferSize > 0)
    ? "network"
    : resources.every((entry) => entry.decodedBodySize > 0)
      ? "http_cache"
      : "unknown";
  const start = Math.min(...resources.map((entry) => entry.startTime));
  const end = Math.max(...resources.map((entry) => entry.startTime + entry.duration));
  return { fetch_ms: Math.round(end - start), cache };
}

export function buildLocalNerTiming({ entries, started, ended, weightsLoadMs, outcome, runtimeOrigin }: {
  entries: ResourceTiming[];
  started: number;
  ended: number;
  weightsLoadMs: number | null;
  outcome: "ready" | "error";
  runtimeOrigin: string;
}) {
  const current = entries.filter((entry) => entry.startTime >= started);
  const weights = summarizeNerResource(current, (url) =>
    url.pathname.endsWith("/model.quant.onnx"));
  const runtime = summarizeNerResource(current, (url) =>
    url.origin === runtimeOrigin && /^\/ort\/[^/]+\/ort-wasm-simd-threaded(?:\.asyncify)?\.(?:mjs|wasm)$/.test(url.pathname));
  return {
    outcome,
    total_load_ms: Math.round(ended - started),
    weights_load_ms: weightsLoadMs === null ? null : Math.round(weightsLoadMs),
    weights_fetch_ms: weights.fetch_ms,
    weights_cache: weights.cache,
    runtime_fetch_ms: runtime.fetch_ms,
    runtime_cache: runtime.cache,
  };
}

export type LocalNerTiming = ReturnType<typeof buildLocalNerTiming>;
