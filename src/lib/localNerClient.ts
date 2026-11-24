import {
  LOCAL_NER_MAX_CHARS,
  type LocalNerSpan,
  type LocalNerStatus,
} from "./localNer.ts";
import type {
  LocalNerWorkerRequest,
  LocalNerWorkerResponse,
} from "./localNer.worker.ts";

/**
 * Main-thread handle for the on-device detector worker. One worker serves
 * the whole page; results are cached per exact text so re-analysis of an
 * unchanged draft never waits on the model.
 */

export type LocalNerDetector = {
  status: () => LocalNerStatus;
  subscribe: (listener: (status: LocalNerStatus) => void) => () => void;
  warm: () => void;
  detect: (text: string) => Promise<LocalNerSpan[]>;
  cached: (text: string) => LocalNerSpan[] | undefined;
};

const CACHE_LIMIT = 32;

type Pending = {
  resolve: (spans: LocalNerSpan[]) => void;
  reject: (error: Error) => void;
};

const INTERACTION_EVENTS = [
  "pointermove",
  "pointerdown",
  "keydown",
  "touchstart",
] as const;

let detector: LocalNerDetector | null = null;

/**
 * Runs `onInteraction` once, on the first sign of a person using the page, so a
 * paste gets a head start without a bot or a bouncer downloading the model.
 * Returns a function that stops listening.
 */
export function onFirstInteraction(
  target: Pick<EventTarget, "addEventListener" | "removeEventListener">,
  onInteraction: () => void
): () => void {
  const stop = () => {
    for (const type of INTERACTION_EVENTS) {
      target.removeEventListener(type, handle);
    }
  };
  const handle = () => {
    stop();
    onInteraction();
  };

  for (const type of INTERACTION_EVENTS) {
    target.addEventListener(type, handle, { passive: true });
  }
  return stop;
}

export function getLocalNerDetector(): LocalNerDetector | null {
  if (typeof window === "undefined" || typeof Worker === "undefined") {
    return null;
  }
  if (!detector) detector = createDetector();
  return detector;
}

function createDetector(): LocalNerDetector {
  let worker: Worker | null = null;
  let status: LocalNerStatus = "idle";
  let nextId = 1;
  const pending = new Map<number, Pending>();
  const inFlight = new Map<string, Promise<LocalNerSpan[]>>();
  const cache = new Map<string, LocalNerSpan[]>();
  const listeners = new Set<(status: LocalNerStatus) => void>();

  const setStatus = (next: LocalNerStatus) => {
    if (status === next) return;
    status = next;
    for (const listener of listeners) listener(status);
  };

  const fail = (message: string) => {
    setStatus("unavailable");
    for (const entry of pending.values()) entry.reject(new Error(message));
    pending.clear();
    inFlight.clear();
    worker?.terminate();
    worker = null;
  };

  const ensureWorker = (): Worker | null => {
    if (worker) return worker;
    if (status === "unavailable") return null;

    try {
      worker = new Worker(new URL("./localNer.worker.ts", import.meta.url), {
        type: "module",
      });
    } catch {
      setStatus("unavailable");
      return null;
    }

    setStatus("loading");
    worker.onmessage = (event: MessageEvent<LocalNerWorkerResponse>) => {
      const response = event.data;
      if (response.type === "timing") return;
      const entry = pending.get(response.id);
      pending.delete(response.id);

      if (response.type === "error") {
        entry?.reject(new Error(response.message));
        // A failed load leaves the detector off for this page; a failed
        // single detection just rejects that request.
        if (status !== "ready") fail(response.message);
        return;
      }

      setStatus("ready");
      if (response.type === "spans") entry?.resolve(response.spans);
      else entry?.resolve([]);
    };
    worker.onerror = (event) => {
      fail(event.message || "Local detector failed to start");
    };

    return worker;
  };

  const send = (
    build: (id: number) => LocalNerWorkerRequest
  ): Promise<LocalNerSpan[]> =>
    new Promise((resolve, reject) => {
      const target = ensureWorker();
      if (!target) {
        reject(new Error("Local detector unavailable"));
        return;
      }
      const id = nextId++;
      pending.set(id, { resolve, reject });
      target.postMessage(build(id));
    });

  const remember = (text: string, spans: LocalNerSpan[]) => {
    cache.set(text, spans);
    if (cache.size > CACHE_LIMIT) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
  };

  return {
    status: () => status,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    warm: () => {
      if (status !== "idle") return;
      send((id) => ({ id, type: "warm" })).catch(() => {
        // Status already reflects the failure.
      });
    },
    cached: (text) => cache.get(text),
    detect: (text) => {
      const hit = cache.get(text);
      if (hit) return Promise.resolve(hit);
      if (text.trim().length === 0 || text.length > LOCAL_NER_MAX_CHARS) {
        return Promise.resolve([]);
      }

      const running = inFlight.get(text);
      if (running) return running;

      const request = send((id) => ({ id, type: "detect", text }))
        .then((spans) => {
          remember(text, spans);
          return spans;
        })
        .finally(() => {
          inFlight.delete(text);
        });
      inFlight.set(text, request);
      return request;
    },
  };
}
