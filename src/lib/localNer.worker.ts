/**
 * Web Worker that runs the on-device PII classifier. Model weights come
 * from the Hugging Face CDN on first use and are kept in the browser Cache
 * API afterwards; prompt text never leaves the worker.
 */
import { env, pipeline } from "@huggingface/transformers";
import type { TokenClassificationPipeline } from "@huggingface/transformers";
import { buildLocalNerTiming, type LocalNerTiming } from "./localNerTiming.ts";
import {
  LOCAL_NER_MODEL_ID,
  LOCAL_NER_MODEL_REVISION,
  chunkTextForLocalNer,
  groupLocalNerTokens,
  mergeLocalNerSpans,
  type LocalNerSpan,
  type LocalNerToken,
} from "./localNer.ts";

export type LocalNerWorkerRequest =
  | { id: number; type: "warm" }
  | { id: number; type: "detect"; text: string };

export type LocalNerWorkerResponse =
  | { type: "timing"; timing: LocalNerTiming }
  | { id: number; type: "ready" }
  | { id: number; type: "spans"; spans: LocalNerSpan[] }
  | { id: number; type: "error"; message: string };

type WorkerScope = {
  postMessage: (message: LocalNerWorkerResponse) => void;
  onmessage: ((event: MessageEvent<LocalNerWorkerRequest>) => void) | null;
};

const scope = self as unknown as WorkerScope;

// Never probe a same-origin /models/ path first; everything comes from the
// Hub so a 404 there is just noise.
env.allowLocalModels = false;
env.allowRemoteModels = true;

// Serve ONNX Runtime from this site (scripts/copy-ort.mjs) instead of its
// default CDN: this code reads raw prompts, so it should come from one origin.
// The suffix matches what Transformers.js picks for the CDN: Safari below 26
// without WebGPU cannot run the asyncify build.
const safariVersion = /Version\/(\d+).*Safari/.exec(self.navigator?.userAgent ?? "");
const ortSuffix =
  safariVersion && Number(safariVersion[1]) < 26 && !("gpu" in self.navigator)
    ? ""
    : ".asyncify";
const ortWasm = env.backends.onnx.wasm;
if (ortWasm) {
  ortWasm.wasmPaths = {
    mjs: `/ort/${env.backends.onnx.versions?.web}/ort-wasm-simd-threaded${ortSuffix}.mjs`,
    wasm: `/ort/${env.backends.onnx.versions?.web}/ort-wasm-simd-threaded${ortSuffix}.wasm`,
  };
}

let classifier: Promise<TokenClassificationPipeline> | null = null;

function loadClassifier(): Promise<TokenClassificationPipeline> {
  if (!classifier) {
    const started = performance.now();
    let weightsStarted: number | null = null;
    let weightsLoadMs: number | null = null;
    const report = (outcome: "ready" | "error") => {
      // Telemetry must never prevent a local privacy feature from working.
      try {
        scope.postMessage({ type: "timing", timing: buildLocalNerTiming({
          entries: performance.getEntriesByType("resource") as PerformanceResourceTiming[],
          started, ended: performance.now(), weightsLoadMs, outcome,
          runtimeOrigin: self.location.origin,
        }) });
      } catch { /* Resource Timing may be unavailable. */ }
    };
    classifier = pipeline("token-classification", LOCAL_NER_MODEL_ID, {
      progress_callback: (progress) => {
        if (!("file" in progress) || progress.file !== "model.quant.onnx") return;
        if (progress.status === "initiate") weightsStarted = performance.now();
        if (progress.status === "done" && weightsStarted !== null) {
          weightsLoadMs = performance.now() - weightsStarted;
        }
      },
      revision: LOCAL_NER_MODEL_REVISION,
      // The repo keeps its ONNX files at the root as model.quant.onnx rather
      // than in the usual onnx/ folder. An empty subfolder plus the fp32
      // dtype produces that exact filename (no dtype suffix).
      subfolder: "",
      model_file_name: "model.quant",
      dtype: "fp32",
      // The int8 graph returns wrong labels on the WebGPU backend, so the
      // model is pinned to WASM, where it was verified.
      device: "wasm",
    }).then((loaded) => {
      report("ready");
      return loaded;
    }).catch((error) => {
      report("error");
      classifier = null;
      throw error;
    });
  }
  return classifier;
}

async function detect(text: string): Promise<LocalNerSpan[]> {
  const ner = await loadClassifier();
  const spans: LocalNerSpan[] = [];

  for (const chunk of chunkTextForLocalNer(text)) {
    const output = (await ner(chunk.text, {
      ignore_labels: [],
    })) as LocalNerToken[] | LocalNerToken[][];
    const tokens = (Array.isArray(output[0]) ? output[0] : output) as
      LocalNerToken[];
    spans.push(...groupLocalNerTokens(chunk.text, tokens, chunk.start));
  }

  return mergeLocalNerSpans(spans);
}

scope.onmessage = async (event) => {
  const request = event.data;

  try {
    if (request.type === "warm") {
      await loadClassifier();
      scope.postMessage({ id: request.id, type: "ready" });
      return;
    }

    const spans = await detect(request.text);
    scope.postMessage({ id: request.id, type: "spans", spans });
  } catch (error) {
    scope.postMessage({
      id: request.id,
      type: "error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};
