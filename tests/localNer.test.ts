import assert from "node:assert/strict";
import test from "node:test";

import {
  alignTokensToText,
  chunkTextForLocalNer,
  confidenceForScore,
  estimateLocalNerTokens,
  groupLocalNerTokens,
  mapLocalNerLabel,
  mergeLocalNerSpans,
  type LocalNerToken,
} from "../src/lib/localNer.ts";
import { onFirstInteraction } from "../src/lib/localNerClient.ts";
import { redactSensitiveText } from "../src/lib/promptRedaction.ts";

test("the model waits for a first interaction, then starts once", () => {
  for (const type of ["pointermove", "pointerdown", "keydown", "touchstart"]) {
    const page = new EventTarget();
    let starts = 0;
    onFirstInteraction(page, () => {
      starts += 1;
    });

    page.dispatchEvent(new Event("scroll"));
    assert.equal(starts, 0, "a page view alone loads nothing");

    page.dispatchEvent(new Event(type));
    page.dispatchEvent(new Event(type));
    page.dispatchEvent(new Event("pointerdown"));
    assert.equal(starts, 1, type);
  }

  const page = new EventTarget();
  let starts = 0;
  const stop = onFirstInteraction(page, () => {
    starts += 1;
  });
  stop();
  page.dispatchEvent(new Event("keydown"));
  assert.equal(starts, 0, "turning detection off stops listening");
});

function tokens(
  entries: Array<[word: string, entity: string, score?: number]>
): LocalNerToken[] {
  return entries.map(([word, entity, score], index) => ({
    word,
    entity,
    score: score ?? 0.95,
    index: index + 1,
  }));
}

test("alignment recovers offsets for lowercased and split word pieces", () => {
  const text = "Email Daniel Okafor at Brightline, please.";
  const aligned = alignTokensToText(
    text,
    tokens([
      ["email", "O"],
      ["daniel", "B-PERSON"],
      ["ok", "B-PERSON"],
      ["##af", "I-PERSON"],
      ["##or", "I-PERSON"],
      ["at", "O"],
      ["bright", "B-ORGANIZATION"],
      ["##line", "I-ORGANIZATION"],
      [",", "O"],
      ["please", "O"],
      [".", "O"],
    ])
  );

  assert.deepEqual(
    aligned.map((token) => text.slice(token.start, token.end)),
    ["Email", "Daniel", "Ok", "af", "or", "at", "Bright", "line", ",", "please", "."]
  );
});

test("alignment skips unknown tokens and still finds later ones", () => {
  const text = "Ping ☃ Sarah now";
  const aligned = alignTokensToText(
    text,
    tokens([
      ["ping", "O"],
      ["[UNK]", "O"],
      ["sarah", "B-PERSON"],
      ["now", "O"],
    ])
  );

  assert.deepEqual(
    aligned.map((token) => text.slice(token.start, token.end)),
    ["Ping", "Sarah", "now"]
  );
});

test("alignment handles accented and CJK text", () => {
  const text = "Je m'appelle Élodie. 我叫王晓明。";
  const aligned = alignTokensToText(
    text,
    tokens([
      ["je", "O"],
      ["m", "O"],
      ["'", "O"],
      ["app", "O"],
      ["##elle", "O"],
      ["elo", "B-PERSON"],
      ["##die", "I-PERSON"],
      [".", "O"],
      ["我", "O"],
      ["叫", "O"],
      ["王", "B-PERSON"],
      ["晓", "I-PERSON"],
      ["明", "I-PERSON"],
    ])
  );

  assert.deepEqual(
    aligned.map((token) => text.slice(token.start, token.end)),
    ["Je", "m", "'", "app", "elle", "Élo", "die", ".", "我", "叫", "王", "晓", "明"]
  );
});

test("grouping joins BIO runs into typed spans with trimmed punctuation", () => {
  const text =
    "I live at 48 Elm Street, Portland and my manager Sarah wants a call on March 3, 2024.";
  const spans = groupLocalNerTokens(
    text,
    tokens([
      ["i", "O"],
      ["live", "O"],
      ["at", "O"],
      ["48", "B-LOCATION", 0.91],
      ["elm", "I-LOCATION", 0.62],
      ["street", "I-LOCATION", 0.9],
      [",", "I-LOCATION", 0.8],
      ["portland", "B-LOCATION", 0.56],
      ["and", "O"],
      ["my", "O"],
      ["manager", "O"],
      ["sarah", "B-PERSON", 0.96],
      ["wants", "O"],
      ["a", "O"],
      ["call", "O"],
      ["on", "O"],
      ["march", "B-DATE_TIME", 0.7],
      ["3", "I-DATE_TIME", 0.7],
      [",", "I-DATE_TIME", 0.7],
      ["202", "I-DATE_TIME", 0.7],
      ["##4", "I-DATE_TIME", 0.7],
      [".", "O"],
    ])
  );

  assert.deepEqual(
    spans.map((span) => [span.type, text.slice(span.start, span.end), span.confidence]),
    [
      ["LOCATION", "48 Elm Street", "high"],
      ["LOCATION", "Portland", "medium"],
      ["PERSON_NAME", "Sarah", "high"],
      ["DATE", "March 3, 2024", "medium"],
    ]
  );
});

test("grouping drops unmapped labels, low scores and single characters", () => {
  const text = "Visit https://example.com, Dr. a Jones, 我";
  const spans = groupLocalNerTokens(
    text,
    tokens([
      ["visit", "O"],
      ["https", "B-URL"],
      ["dr", "B-HONORIFIC"],
      ["a", "B-PERSON", 0.9],
      ["jones", "B-PERSON", 0.2],
      ["我", "B-PERSON", 0.9],
    ])
  );

  assert.deepEqual(spans, []);
});

test("grouping drops structured spans that do not look like their type", () => {
  const text = "You can cc rakesh@brightline.co or call 503-555-0142 or ext 12.";
  const spans = groupLocalNerTokens(
    text,
    tokens([
      ["you", "O"],
      ["can", "O"],
      ["cc", "B-EMAIL_ADDRESS", 0.86],
      ["rake", "B-EMAIL_ADDRESS", 0.9],
      ["##sh", "I-EMAIL_ADDRESS", 0.9],
      ["@", "I-EMAIL_ADDRESS", 0.9],
      ["bright", "I-EMAIL_ADDRESS", 0.9],
      ["##line", "I-EMAIL_ADDRESS", 0.9],
      [".", "I-EMAIL_ADDRESS", 0.9],
      ["co", "I-EMAIL_ADDRESS", 0.9],
      ["or", "O"],
      ["call", "O"],
      ["503", "B-PHONE_NUMBER", 0.9],
      ["-", "I-PHONE_NUMBER", 0.9],
      ["555", "I-PHONE_NUMBER", 0.9],
      ["-", "I-PHONE_NUMBER", 0.9],
      ["01", "I-PHONE_NUMBER", 0.9],
      ["##42", "I-PHONE_NUMBER", 0.9],
      ["or", "O"],
      ["ext", "O"],
      ["12", "B-PHONE_NUMBER", 0.9],
      [".", "O"],
    ])
  );

  assert.deepEqual(
    spans.map((span) => [span.type, text.slice(span.start, span.end)]),
    [
      ["EMAIL", "rakesh@brightline.co"],
      ["PHONE", "503-555-0142"],
    ]
  );
});

test("grouping joins a name the model restarted mid-way", () => {
  const text = "Meeting with Daniel Okafor and Mia Chen, then Tom.";
  const spans = groupLocalNerTokens(
    text,
    tokens([
      ["meeting", "O"],
      ["with", "O"],
      ["daniel", "B-PERSON", 0.99],
      ["ok", "B-PERSON", 0.64],
      ["##af", "I-PERSON", 0.97],
      ["##or", "I-PERSON", 0.97],
      ["and", "O"],
      ["mia", "B-PERSON", 0.95],
      ["chen", "I-PERSON", 0.95],
      [",", "O"],
      ["then", "O"],
      ["tom", "B-PERSON", 0.9],
      [".", "O"],
    ])
  );

  assert.deepEqual(
    spans.map((span) => text.slice(span.start, span.end)),
    ["Daniel Okafor", "Mia Chen", "Tom"]
  );
});

test("grouping applies the chunk offset", () => {
  const text = "Call Mia.";
  const spans = groupLocalNerTokens(
    text,
    tokens([
      ["call", "O"],
      ["mia", "B-PERSON"],
      [".", "O"],
    ]),
    100
  );

  assert.deepEqual(
    spans.map((span) => [span.start, span.end]),
    [[105, 108]]
  );
});

test("label mapping covers the model's useful labels only", () => {
  assert.equal(mapLocalNerLabel("PERSON"), "PERSON_NAME");
  assert.equal(mapLocalNerLabel("EMAIL_ADDRESS"), "EMAIL");
  assert.equal(mapLocalNerLabel("CREDIT_CARD"), "PAYMENT_CARD");
  assert.equal(mapLocalNerLabel("PASSWORD"), "SECRET");
  assert.equal(mapLocalNerLabel("IBAN_CODE"), "BANK_ACCOUNT");
  assert.equal(mapLocalNerLabel("URL"), null);
  assert.equal(mapLocalNerLabel("TITLE"), null);
  assert.equal(mapLocalNerLabel("O"), null);
});

test("confidence thresholds", () => {
  assert.equal(confidenceForScore(0.95), "high");
  assert.equal(confidenceForScore(0.8), "high");
  assert.equal(confidenceForScore(0.6), "medium");
  assert.equal(confidenceForScore(0.3), null);
  assert.equal(confidenceForScore(Number.NaN), null);
});

test("chunking keeps short text whole and splits long text at sentences", () => {
  assert.deepEqual(chunkTextForLocalNer("Hello there."), [
    { start: 0, text: "Hello there." },
  ]);

  const sentence =
    "Yesterday I spoke with Priya Natarajan about the quarterly budget. ";
  const text = sentence.repeat(40);
  const chunks = chunkTextForLocalNer(text);

  assert.ok(chunks.length > 1, "long text produces several chunks");
  assert.equal(
    chunks.map((chunk) => chunk.text).join(""),
    text,
    "chunks cover the whole text in order"
  );
  for (const chunk of chunks) {
    assert.equal(text.slice(chunk.start, chunk.start + chunk.text.length), chunk.text);
    assert.ok(estimateLocalNerTokens(chunk.text) <= 320);
    assert.ok(chunk.text.endsWith(". "), "chunks end on a sentence boundary");
  }
});

test("chunking cuts an oversized run without boundaries", () => {
  const text = "x".repeat(50) + " " + "王".repeat(900) + " end.";
  const chunks = chunkTextForLocalNer(text);

  assert.equal(chunks.map((chunk) => chunk.text).join(""), text);
  for (const chunk of chunks) {
    assert.ok(estimateLocalNerTokens(chunk.text) <= 320);
  }
});

test("merging keeps the better of two overlapping spans", () => {
  const merged = mergeLocalNerSpans([
    { type: "PERSON_NAME", start: 0, end: 5, confidence: "medium", score: 0.5, label: "PERSON" },
    { type: "ORGANIZATION", start: 3, end: 9, confidence: "high", score: 0.9, label: "ORGANIZATION" },
    { type: "LOCATION", start: 20, end: 26, confidence: "high", score: 0.8, label: "LOCATION" },
  ]);

  assert.deepEqual(
    merged.map((span) => [span.type, span.start, span.end]),
    [
      ["ORGANIZATION", 3, 9],
      ["LOCATION", 20, 26],
    ]
  );
});

test("redaction applies model spans and lets regex rules win overlaps", () => {
  const text =
    "Meeting with Daniel Okafor at Brightline Logistics; mail rakesh.menon@brightline.co.";
  const emailStart = text.indexOf("rakesh");
  const result = redactSensitiveText(text, {
    privacyMode: "standard",
    localNerSpans: [
      {
        type: "PERSON_NAME",
        start: text.indexOf("Daniel"),
        end: text.indexOf("Daniel") + "Daniel Okafor".length,
        confidence: "high",
        score: 0.98,
        label: "PERSON",
      },
      {
        type: "ORGANIZATION",
        start: text.indexOf("Brightline"),
        end: text.indexOf("Brightline") + "Brightline Logistics".length,
        confidence: "high",
        score: 0.97,
        label: "ORGANIZATION",
      },
      // Overlaps the regex email match; the regex span takes precedence.
      {
        type: "PERSON_NAME",
        start: emailStart,
        end: emailStart + 6,
        confidence: "high",
        score: 0.9,
        label: "PERSON",
      },
    ],
  });

  assert.equal(
    result.text,
    "Meeting with [PERSON_NAME_1] at [ORGANIZATION_1]; mail [EMAIL_1]."
  );
  assert.deepEqual(
    result.entities.map((entity) => [entity.type, entity.source]),
    [
      ["PERSON_NAME", "ner"],
      ["ORGANIZATION", "ner"],
      ["EMAIL", "regex"],
    ]
  );
});

test("redaction ignores model spans with offsets outside the text", () => {
  const result = redactSensitiveText("Short text.", {
    privacyMode: "strict",
    localNerSpans: [
      { type: "PERSON_NAME", start: 5, end: 40, confidence: "high", score: 0.9, label: "PERSON" },
      { type: "PERSON_NAME", start: -1, end: 3, confidence: "high", score: 0.9, label: "PERSON" },
      { type: "PERSON_NAME", start: 4, end: 4, confidence: "high", score: 0.9, label: "PERSON" },
    ],
  });

  assert.equal(result.text, "Short text.");
  assert.equal(result.entities.length, 0);
});

test("medium-confidence model spans follow the privacy mode", () => {
  const text = "Ask Portland.";
  const span = {
    type: "LOCATION" as const,
    start: 4,
    end: 12,
    confidence: "medium" as const,
    score: 0.6,
    label: "LOCATION",
  };

  assert.equal(
    redactSensitiveText(text, { privacyMode: "standard", localNerSpans: [span] }).text,
    "Ask Portland."
  );
  assert.equal(
    redactSensitiveText(text, { privacyMode: "strict", localNerSpans: [span] }).text,
    "Ask [LOCATION_1]."
  );
});

test("a single lowercase word tagged as a name is held at medium", () => {
  // The model scores "pong" 0.93 PERSON in "Reply with one word: pong".
  const text = "Reply with one word: pong";
  const [span] = groupLocalNerTokens(
    text,
    tokens([
      ["reply", "O"],
      ["with", "O"],
      ["one", "O"],
      ["word", "O"],
      [":", "O"],
      ["po", "B-PERSON", 0.92],
      ["##ng", "I-PERSON", 0.93],
    ]),
    0
  );
  assert.equal(text.slice(span.start, span.end), "pong");
  assert.equal(span.confidence, "medium");
});

test("capitalised and multi-word lowercase names stay high", () => {
  const capitalised = groupLocalNerTokens(
    "Meet Ana today",
    tokens([
      ["meet", "O"],
      ["ana", "B-PERSON", 0.98],
      ["today", "O"],
    ]),
    0
  );
  assert.equal(capitalised[0]?.confidence, "high");

  const lowercaseFullName = groupLocalNerTokens(
    "call john smith tomorrow",
    tokens([
      ["call", "O"],
      ["john", "B-PERSON", 0.91],
      ["smith", "B-PERSON", 0.9],
      ["tomorrow", "O"],
    ]),
    0
  );
  assert.equal(lowercaseFullName.length, 1);
  assert.equal(lowercaseFullName[0]?.confidence, "high");
});

test("a name fragment inside a word is dropped, a secret fragment is kept", () => {
  assert.deepEqual(
    groupLocalNerTokens(
      "Write a haiku about rain",
      tokens([
        ["write", "O"],
        ["a", "O"],
        ["hai", "O"],
        ["##ku", "I-PERSON", 0.95],
        ["about", "O"],
        ["rain", "O"],
      ]),
      0
    ),
    []
  );

  const secret = groupLocalNerTokens(
    "token ab12cd34ef56gh78",
    tokens([
      ["token", "O"],
      ["ab", "O"],
      ["##12cd34ef56gh78", "I-PASSWORD", 0.95],
    ]),
    0
  );
  assert.equal(secret[0]?.type, "SECRET");
});
