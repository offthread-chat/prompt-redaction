# Offthread prompt redaction

This repository contains the TypeScript that Offthread uses to replace sensitive values with placeholders before sending chat text to a model. It also includes the browser worker for optional named-entity recognition and the code that restores values in replies.

## Try the pattern detector

Run this example from the repository root with Bun. The pattern detector works without model weights.

```ts
import { redactSensitiveText } from "./src/lib/promptRedaction.ts";
import { restorePlaceholders } from "./src/lib/redactedCloudMode.ts";

const result = redactSensitiveText("Email dana@example.com.", { privacyMode: "standard" });
console.log(result.text); // Email [EMAIL_1].
console.log(restorePlaceholders("Ask [EMAIL_1] first.", result.placeholderMap));
// Ask dana@example.com first.
```

Keep the placeholder map on the user's device. It contains the original values for restorable entries. Review a draft before sending it. The detector can miss names, dates, and other identifying details. See the [measured results and examples of misses](https://offthread.chat/learn/redaction-benchmark).

## Use the optional browser model

Run `bun install --frozen-lockfile` and `bun run prepare:ort`. Serve the generated `public/ort/` directory at `/ort/` and bundle the module worker in `src/lib/localNer.worker.ts` with the client in `src/lib/localNerClient.ts`. The worker fetches pinned model weights from Hugging Face on first use. The model identifier and revision are in `src/lib/localNer.ts`.

Pass the spans returned by the detector to the pattern engine for the same input text. The synchronous example above runs the pattern rules alone.

## Verify this snapshot

Run `bun test` for the fixture tests covering detection, token alignment, placeholder restoration, and worker timing. The source comes from Offthread web revision `a152885f1396e09283872772d0eeab077882e9a2`. The standalone worker client omits the app's optional analytics callback. The detector rules, worker, alignment, and restoration code are copied verbatim.

The source in this repository is available under the [MIT license](LICENSE). Model weights and runtime dependencies are distributed by their respective publishers.
