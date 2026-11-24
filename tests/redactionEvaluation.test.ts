import assert from "node:assert/strict";
import test from "node:test";

import {
  redactSensitiveText,
  type RedactionType,
} from "../src/lib/promptRedaction.ts";

type EvaluationFixture = {
  name: string;
  group: string;
  input: string;
  expectedTypes: RedactionType[];
  absentValues: string[];
  mode?: "strict" | "standard" | "manual" | "off";
};

const FIXTURES: EvaluationFixture[] = [
  {
    name: "structured email and token",
    group: "Structured secrets and IDs",
    input: "Email jane@example.com with Bearer abcdefghijklmnopqrst.",
    expectedTypes: ["EMAIL", "TOKEN"],
    absentValues: ["jane@example.com", "abcdefghijklmnopqrst"],
  },
  {
    name: "conversational identity",
    group: "Conversational identity",
    input: "I'm John, 22 years old, living in Miami.",
    expectedTypes: ["PERSON_NAME", "AGE", "LOCATION"],
    absentValues: ["John", "22", "Miami"],
  },
  {
    name: "employer and organization context",
    group: "Employers, schools, and organizations",
    input: "I work at Acme Labs and I attend University of Miami.",
    expectedTypes: ["ORGANIZATION", "SCHOOL"],
    absentValues: ["Acme Labs", "University of Miami"],
  },
  {
    name: "health and family context",
    group: "Health/legal/finance contexts",
    input: "My son has symptoms and my doctor said to check medication.",
    expectedTypes: ["SENSITIVE_CONTEXT"],
    absentValues: ["My son", "symptoms", "my doctor", "medication"],
  },
  {
    name: "location and address",
    group: "Locations and addresses",
    input: "Mail it to 123 Ocean Drive, Miami, FL 33139.",
    expectedTypes: ["ADDRESS"],
    absentValues: ["123 Ocean Drive"],
  },
  {
    name: "filename-like sensitive term",
    group: "Attachments and filenames",
    input: "client-ssn-123-45-6789.txt",
    expectedTypes: ["SSN"],
    absentValues: ["123-45-6789"],
  },
  {
    name: "false positive guard for generic capitalized product copy",
    group: "False-positive cases",
    input: "Private Chat helps teams write faster.",
    expectedTypes: [],
    absentValues: [],
  },
  {
    name: "multilingual smoke test preserves unsupported language",
    group: "Multilingual smoke tests",
    input: "Je m'appelle Jean et je vis a Paris.",
    expectedTypes: [],
    absentValues: [],
  },
];

test("redaction evaluation fixtures cover planned detector groups", () => {
  const groups = new Set(FIXTURES.map((fixture) => fixture.group));

  assert.deepEqual(
    Array.from(groups).sort(),
    [
      "Attachments and filenames",
      "Conversational identity",
      "Employers, schools, and organizations",
      "False-positive cases",
      "Health/legal/finance contexts",
      "Locations and addresses",
      "Multilingual smoke tests",
      "Structured secrets and IDs",
    ].sort()
  );
});

for (const fixture of FIXTURES) {
  test(`redaction evaluation: ${fixture.name}`, () => {
    const result = redactSensitiveText(fixture.input, {
      privacyMode: fixture.mode ?? "strict",
    });
    const detectedTypes = new Set(result.entities.map((entity) => entity.type));

    for (const type of fixture.expectedTypes) {
      assert.equal(
        detectedTypes.has(type),
        true,
        `${fixture.name} should detect ${type}`
      );
    }

    for (const value of fixture.absentValues) {
      assert.equal(
        result.text.includes(value),
        false,
        `${fixture.name} should remove ${value} from provider-bound text`
      );
    }
  });
}
