import assert from "node:assert/strict";
import test from "node:test";

import {
  createRedactionSession,
  redactSensitiveText,
  redactionEntityId,
} from "../src/lib/promptRedaction.ts";
import { linkCarriesRestoredValue, restorePlaceholders } from "../src/lib/redactedCloudMode.ts";

test("redaction keeps stable placeholders across prompt and attachment analysis", () => {
  const session = createRedactionSession();

  const prompt = redactSensitiveText(
    "Email alice@example.com before sending.",
    {},
    session
  );
  const attachment = redactSensitiveText(
    "alice@example.com paid with 4111 1111 1111 1111.",
    { sourceLocation: "attachment", sourceLabel: "notes.txt" },
    session
  );

  assert.equal(prompt.text, "Email [EMAIL_1] before sending.");
  assert.equal(
    attachment.text,
    "[EMAIL_1] paid with [PAYMENT_CARD_1]."
  );
  assert.equal(session.counts.EMAIL, 1);
  assert.equal(session.counts.PAYMENT_CARD, 1);
  assert.deepEqual(
    Array.from(session.placeholderMap.values()).map((entry) => entry.placeholder),
    ["[EMAIL_1]", "[PAYMENT_CARD_1]"]
  );
});

test("redaction decisions can edit placeholders or allow a value", () => {
  const entityId = redactionEntityId("EMAIL", "alice@example.com", "prompt");
  const edited = redactSensitiveText("alice@example.com", {
    decisions: {
      [entityId]: {
        placeholder: "client_email",
      },
    },
  });
  const allowed = redactSensitiveText("alice@example.com", {
    decisions: {
      [entityId]: {
        action: "allow",
      },
    },
  });

  assert.equal(edited.text, "[CLIENT_EMAIL]");
  assert.equal(edited.placeholderMap[0]?.placeholder, "[CLIENT_EMAIL]");
  assert.equal(allowed.text, "alice@example.com");
  assert.equal(allowed.placeholderMap.length, 0);
});

test("custom sensitive terms are detected and mapped locally", () => {
  const result = redactSensitiveText("Project Atlas is confidential.", {
    customTerms: ["Project Atlas"],
  });

  assert.equal(result.text, "[CUSTOM_TERM_1] is confidential.");
  assert.equal(result.entities[0]?.type, "CUSTOM_TERM");
  assert.equal(result.placeholderMap[0]?.originalValue, "Project Atlas");
});

test("self-disclosed identity details are redacted from conversational prompts", () => {
  const result = redactSensitiveText("I'm John, 22 years old, living in Miami");

  assert.equal(
    result.text,
    "I'm [PERSON_NAME_1], [AGE_1] years old, living in [LOCATION_1]"
  );
  assert.equal(result.counts.PERSON_NAME, 1);
  assert.equal(result.counts.AGE, 1);
  assert.equal(result.counts.LOCATION, 1);
  assert.deepEqual(
    result.placeholderMap.map((entry) => entry.originalValue),
    ["John", "22", "Miami"]
  );
});

test("standard mode surfaces medium semantic detections without auto-redacting them", () => {
  const result = redactSensitiveText(
    "I work at Acme Labs and my therapist said call John.",
    { privacyMode: "standard" }
  );

  assert.equal(result.text, "I work at Acme Labs and my therapist said call John.");
  assert.equal(result.changed, false);
  assert.equal(result.entities.length, 2);
  assert.equal(result.counts.ORGANIZATION, 1);
  assert.equal(result.counts.SENSITIVE_CONTEXT, 1);
  assert.deepEqual(
    result.entities.map((entity) => entity.action),
    ["allow", "allow"]
  );
  assert.equal(result.placeholderMap.length, 0);
});

test("strict mode redacts semantic and context detections", () => {
  const result = redactSensitiveText(
    "John from South Beach works at Acme Labs. My son has symptoms on May 3.",
    { privacyMode: "strict" }
  );

  assert.equal(
    result.text,
    "[PERSON_NAME_1] from [LOCATION_1] works at Acme Labs. [SENSITIVE_CONTEXT_1] has [SENSITIVE_CONTEXT_2] on [DATE_1]."
  );
  assert.equal(result.entities.find((entity) => entity.type === "PERSON_NAME")?.source, "ner");
  assert.equal(result.entities.find((entity) => entity.type === "DATE")?.confidence, "medium");
  assert.equal(result.counts.PERSON_NAME, 1);
  assert.equal(result.counts.LOCATION, 1);
  assert.equal(result.counts.SENSITIVE_CONTEXT, 2);
  assert.equal(result.counts.DATE, 1);
});

test("custom terms win overlap resolution over structured entities", () => {
  const result = redactSensitiveText("Send Project Atlas to atlas@example.com.", {
    customTerms: ["Project Atlas"],
  });

  assert.equal(result.text, "Send [CUSTOM_TERM_1] to [EMAIL_1].");
  assert.deepEqual(
    result.entities.map((entity) => entity.type),
    ["CUSTOM_TERM", "EMAIL"]
  );
});

test("private vocabulary supports typed and disabled entries", () => {
  const result = redactSensitiveText("Jane Doe works at Acme Labs for Atlas.", {
    customTerms: ["PERSON_NAME: Jane Doe", "[ORGANIZATION] Acme Labs", "# Atlas"],
  });

  assert.equal(
    result.text,
    "[PERSON_NAME_1] works at [ORGANIZATION_1] for Atlas."
  );
  assert.deepEqual(
    result.entities.map((entity) => entity.type),
    ["PERSON_NAME", "ORGANIZATION"]
  );
});

test("distinct url credentials get distinct entities and placeholders", () => {
  const result = redactSensitiveText(
    "prod https://u1:p1aa@10.0.0.5:5432/db and stage https://u2:p2bb@10.0.0.9:5432/db"
  );

  assert.equal(
    result.text,
    "prod https://[SECRET_1]@[IP_ADDRESS_1]:5432/db and stage https://[SECRET_2]@[IP_ADDRESS_2]:5432/db"
  );

  const secrets = result.entities.filter((entity) => entity.type === "SECRET");
  assert.equal(secrets.length, 2);
  assert.notEqual(secrets[0]?.id, secrets[1]?.id);
  assert.equal(secrets[0]?.originalValue, "u1:p1aa");
  assert.equal(secrets[1]?.originalValue, "u2:p2bb");
});

test("url credentials are never retained in the placeholder map", () => {
  const result = redactSensitiveText("Connect to https://u1:p1aa@10.0.0.5:5432/db.");

  assert.equal(result.text, "Connect to https://[SECRET_1]@[IP_ADDRESS_1]:5432/db.");
  assert.equal(
    result.placeholderMap.some((entry) => entry.type === "SECRET"),
    false
  );
  assert.equal(
    JSON.stringify(result.placeholderMap).includes("p1aa"),
    false
  );
});

test("restoring a message leaves url credential placeholders intact", () => {
  const result = redactSensitiveText(
    "prod https://u1:p1aa@10.0.0.5:5432/db and stage https://u2:p2bb@10.0.0.9:5432/db"
  );

  assert.equal(
    restorePlaceholders(result.text, result.placeholderMap),
    "prod https://[SECRET_1]@10.0.0.5:5432/db and stage https://[SECRET_2]@10.0.0.9:5432/db"
  );
});

test("allowing one url credential does not allow the other", () => {
  const result = redactSensitiveText(
    "prod https://u1:p1aa@10.0.0.5:5432/db and stage https://u2:p2bb@10.0.0.9:5432/db"
  );
  const secrets = result.entities.filter((entity) => entity.type === "SECRET");
  const decisions = { [secrets[0]!.id]: { action: "allow" as const } };

  const reread = redactSensitiveText(
    "prod https://u1:p1aa@10.0.0.5:5432/db and stage https://u2:p2bb@10.0.0.9:5432/db",
    { decisions }
  );

  assert.equal(
    reread.text,
    "prod https://u1:p1aa@[IP_ADDRESS_1]:5432/db and stage https://[SECRET_2]@[IP_ADDRESS_2]:5432/db"
  );
  assert.equal(
    reread.entities.filter((entity) => entity.action === "allow").length,
    1
  );
});

test("address redaction stops at the end of the address", () => {
  const result = redactSensitiveText(
    "I live at 48 Elm Street, Portland and my manager Sarah wants me to explain. My work phone is 503-555-0142.",
    { privacyMode: "standard" }
  );

  assert.equal(
    result.text,
    "I live at [ADDRESS_1] and my manager Sarah wants me to explain. My work phone is [PHONE_1]."
  );
  assert.equal(result.placeholderMap[0]?.originalValue, "48 Elm Street, Portland");
});

test("address redaction keeps unit, city, state and ZIP", () => {
  const cases: Array<[string, string]> = [
    ["Ship to 123 Main St, Springfield, CA 94105 today.", "Ship to [ADDRESS_1] today."],
    ["Office: 500 Market Street Suite 300, San Francisco, CA 94105.", "Office: [ADDRESS_1]."],
    ["Mail 12 3rd St. Louis Ave, St. Louis MO 63101 please", "Mail [ADDRESS_1] please"],
    ["my place is 48 elm street and it is small", "my place is [ADDRESS_1] and it is small"],
  ];

  for (const [input, expected] of cases) {
    assert.equal(redactSensitiveText(input, { privacyMode: "standard" }).text, expected, input);
  }
});

test("address redaction does not swallow the following sentence", () => {
  const cases: Array<[string, string]> = [
    [
      "Meet at 9 Park Avenue. Then we walk to the park.",
      "Meet at [ADDRESS_1]. Then we walk to the park.",
    ],
    [
      "Meet at 9 Park Avenue. Sarah Will Join Us Later.",
      "Meet at [ADDRESS_1]. Sarah Will Join Us Later.",
    ],
    [
      "Send it to 12 Oak St. Tomorrow is fine.",
      "Send it to [ADDRESS_1]. Tomorrow is fine.",
    ],
  ];

  for (const [input, expected] of cases) {
    const result = redactSensitiveText(input, { privacyMode: "standard" });
    assert.equal(result.text, expected, input);
  }
});

test("words after 'account' are not taken for account numbers", async () => {
  const { redactSensitiveText } = await import("../src/lib/promptRedaction.ts");
  for (const text of [
    "Accountability matters a lot here",
    "a culture of accountability and open communication",
    "my account settings page",
  ]) {
    assert.equal(redactSensitiveText(text).text, text);
  }
  assert.equal(
    redactSensitiveText("account number 12345678").text,
    "account number [BANK_ACCOUNT_1]"
  );
});

test("phone numbers keep their prefix inside the placeholder", () => {
  for (const phone of [
    "+1 415 555 0134",
    "(415) 555-0134",
    "+44 20 7946 0958",
    "+86 138 0013 8000",
    "+49 (30) 901820",
  ]) {
    const { text } = redactSensitiveText(`Call ${phone} today`);
    assert.equal(text, "Call [PHONE_1] today", phone);
  }
});

test("phone rule leaves arithmetic, columns and short numbers alone", () => {
  for (const text of ["1+2345678", "Total +12 items", "Version 2.10.3", "+5\n10\n15\n20\n25\n30"]) {
    assert.equal(redactSensitiveText(text).text, text);
  }
});

test("a link holding a restored value is detected, a plain link or mailto is not", () => {
  const map = [{ placeholder: "[EMAIL_1]", originalValue: "maria@acme.com" }] as Parameters<
    typeof linkCarriesRestoredValue
  >[1];
  assert.equal(linkCarriesRestoredValue("https://evil.example/x?e=maria@acme.com", map), true);
  assert.equal(linkCarriesRestoredValue("https://evil.example/x?e=maria%40acme.com", map), true);
  assert.equal(linkCarriesRestoredValue("mailto:maria@acme.com", map), false);
  assert.equal(linkCarriesRestoredValue("https://example.com/docs", map), false);
  assert.equal(linkCarriesRestoredValue("https://maria@acme.com.evil.example/", map), true);
  assert.equal(linkCarriesRestoredValue("https://evil.example/?x=%ZZ&e=maria%40acme.com", map), true);

  const name = [{ placeholder: "[PERSON_NAME_1]", originalValue: "Li" }] as typeof map;
  assert.equal(linkCarriesRestoredValue("https://example.com/wiki/List_of_x", name), false);
  assert.equal(linkCarriesRestoredValue("https://evil.example/?n=Li", name), true);
});
