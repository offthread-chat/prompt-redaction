import type { LocalNerSpan } from "./localNer.ts";

export type RedactionType =
  | "ADDRESS"
  | "AGE"
  | "BANK_ACCOUNT"
  | "CONNECTION_URL"
  | "CUSTOM_TERM"
  | "DATE"
  | "DOB"
  | "EMAIL"
  | "IP_ADDRESS"
  | "JOB_TITLE"
  | "LOCATION"
  | "ORGANIZATION"
  | "PAYMENT_CARD"
  | "PERSON_NAME"
  | "PHONE"
  | "PRIVATE_KEY"
  | "SCHOOL"
  | "SECRET"
  | "SENSITIVE_CONTEXT"
  | "SSN"
  | "TOKEN";

export type RedactionSourceLocation = "prompt" | "filename" | "attachment";

export type RedactionConfidence = "high" | "medium" | "low";

export type RedactionDetectorSource =
  | "custom"
  | "regex"
  | "ner"
  | "context"
  | "attachment";

export type RedactionPolicyMode = "strict" | "standard" | "manual" | "off";

export type RedactionAction = "redact" | "allow";

export type RedactionDecision = {
  action?: RedactionAction;
  placeholder?: string;
};

export type DetectionSpan = {
  type: RedactionType;
  start: number;
  end: number;
  value: string;
  confidence: RedactionConfidence;
  source: RedactionDetectorSource;
  sourceLocation: RedactionSourceLocation;
  sourceLabel?: string;
  /**
   * Whether the matched value may be retained in the restore map.
   * Secrets that must never be kept around (currently inline URL credentials)
   * set this to false so they are redacted but cannot be substituted back.
   */
  retainOriginalValue: boolean;
};

export type RedactionEntity = {
  id: string;
  type: RedactionType;
  originalValue: string;
  placeholder: string;
  confidence: RedactionConfidence;
  source: RedactionDetectorSource;
  sourceLocation: RedactionSourceLocation;
  sourceLabel?: string;
  defaultAction: RedactionAction;
  action: RedactionAction;
};

export type PlaceholderMapEntry = {
  placeholder: string;
  originalValue: string;
  type: RedactionType;
};

export type RedactionResult = {
  text: string;
  changed: boolean;
  counts: Partial<Record<RedactionType, number>>;
  entities: RedactionEntity[];
  placeholderMap: PlaceholderMapEntry[];
  spans: DetectionSpan[];
};

type RedactionState = {
  counts: Partial<Record<RedactionType, number>>;
  entities: RedactionEntity[];
  placeholderMap: Map<string, PlaceholderMapEntry>;
  placeholderSeen: Map<string, SeenPlaceholder>;
  seen: Map<string, SeenRedaction>;
};

type SeenRedaction = {
  entity: RedactionEntity;
  placeholderIndex: number;
};

type SeenPlaceholder = {
  placeholder: string;
  placeholderIndex: number;
};

type RedactionContext = {
  customTerms: NormalizedCustomTerm[];
  decisions: Record<string, RedactionDecision>;
  privacyMode: RedactionPolicyMode;
  sourceLocation: RedactionSourceLocation;
  sourceLabel?: string;
  localNerSpans: LocalNerSpan[];
};

type NormalizedCustomTerm = {
  value: string;
  type: RedactionType;
};

type RedactionPatternRule = {
  type: RedactionType;
  pattern: RegExp;
  confidence: RedactionConfidence;
  source?: RedactionDetectorSource;
  valueGroup?: number;
  valueForEntity?: string | ((value: string, match: RegExpExecArray) => string);
  /**
   * Set to false when the matched value is itself a credential that must not
   * be persisted into the placeholder map used for restoring redacted text.
   */
  retainOriginalValue?: boolean;
  filter?: (value: string, match: RegExpExecArray) => boolean;
};

export type RedactionOptions = {
  customTerms?: string[];
  decisions?: Record<string, RedactionDecision>;
  privacyMode?: RedactionPolicyMode;
  sourceLocation?: RedactionSourceLocation;
  sourceLabel?: string;
  /**
   * Spans found by the on-device model for exactly this input. Offsets must
   * refer to `input`; the caller is responsible for not reusing spans
   * computed for a different text.
   */
  localNerSpans?: LocalNerSpan[];
};

export type RedactionSession = RedactionState;

const STRUCTURED_RULES: RedactionPatternRule[] = [
  {
    type: "PRIVATE_KEY",
    confidence: "high",
    pattern:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    type: "CONNECTION_URL",
    confidence: "high",
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|sftp|ftp):\/\/[^\s"'<>\\]+/gi,
  },
  {
    type: "SECRET",
    confidence: "high",
    pattern: /\bhttps?:\/\/([^/\s:@]+:[^/\s@]+)@/gi,
    valueGroup: 1,
    // The matched text is a live credential. It must stay out of the
    // placeholder map so it is never retained for restoring, but it still has
    // to drive entity identity so distinct credentials stay distinct.
    retainOriginalValue: false,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\bBearer\s+([A-Za-z0-9._~+/=-]{12,})/gi,
    valueGroup: 1,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "TOKEN",
    confidence: "high",
    pattern:
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    type: "SECRET",
    confidence: "high",
    pattern:
      /\b(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|password|passwd|pwd|authorization|auth[_-]?token|private[_-]?key|session[_-]?secret|database[_-]?url|db[_-]?url)\b\s*[:=]\s*(["']?)([^"'\s,;`<>]{6,})(\1)/gi,
    valueGroup: 2,
  },
  {
    type: "EMAIL",
    confidence: "high",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    type: "PERSON_NAME",
    confidence: "high",
    pattern:
      /\b(?:[Mm]y name is|[Nn]ame is|[Cc]all me|[Ii](?:'|\u2019)m|[Ii] am)\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,2})\b/g,
    valueGroup: 1,
  },
  {
    type: "AGE",
    confidence: "high",
    pattern:
      /\b(\d{1,3})(\s*(?:years?\s+old|yrs?\s+old|y\/o|yo))\b/gi,
    valueGroup: 1,
    filter: isLikelyAge,
  },
  {
    type: "AGE",
    confidence: "high",
    pattern: /\b[Aa]ge\s*[:=]?\s*(\d{1,3})\b/g,
    valueGroup: 1,
    filter: isLikelyAge,
  },
  {
    type: "LOCATION",
    confidence: "high",
    pattern:
      /\b(?:[Ll]iving|[Bb]ased|[Ll]ocated|[Rr]esiding)\s+in\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\b/g,
    valueGroup: 1,
  },
  {
    type: "LOCATION",
    confidence: "high",
    pattern:
      /\b[Ff]rom\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\b/g,
    valueGroup: 1,
  },
  {
    type: "SSN",
    confidence: "high",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "PHONE",
    confidence: "high",
    pattern:
      // International numbers need the "+" (8 to 15 digits, as in E.164), so a
      // long order number is not mistaken for one. The lookbehind, unlike \b,
      // lets the match include a leading "+" or "(".
      /(?<![\w+])(?:\+\d(?:[ .-]?\(?\d\)?){7,14}|(?:1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b/g,
  },
  {
    type: "DOB",
    confidence: "high",
    pattern:
      /\b(?:dob|date of birth|birthdate)\s*[:=]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})/gi,
    valueGroup: 1,
  },
  {
    type: "BANK_ACCOUNT",
    confidence: "high",
    pattern:
      // The keyword must end at a word boundary ("accountability" is not a
      // label) and the value must hold at least four digits, so ordinary
      // words after "account" are not taken for account numbers.
      /\b(?:account|acct|routing|iban)\b\s*(?:number|no\.?|#)?\s*[:=]?\s*((?=(?:[A-Z -]*\d){4})[A-Z0-9][A-Z0-9 -]{7,33})\b/gi,
    valueGroup: 1,
  },
  {
    type: "IP_ADDRESS",
    confidence: "high",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  },
  {
    type: "ADDRESS",
    confidence: "high",
    // Street number, up to five name words, a street type, then optional
    // unit, city, state and ZIP. The city must follow a comma and consist of
    // capitalized words so the match stops at the end of the address instead
    // of running on into the rest of the sentence. The pattern is
    // case-sensitive on purpose for that reason; the street type spells out
    // both cases.
    pattern:
      /\b\d{1,6}[A-Za-z]?\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s+(?:[Ss]treet|[Ss]t|[Aa]venue|[Aa]ve|[Rr]oad|[Rr]d|[Bb]oulevard|[Bb]lvd|[Ll]ane|[Ll]n|[Dd]rive|[Dd]r|[Cc]ourt|[Cc]t|[Ww]ay|[Pp]lace|[Pp]l|[Tt]errace|[Tt]er)\b(?:\.(?=,))?(?:,?\s+(?:[Aa]pt|[Ss]uite|[Ss]te|[Uu]nit|#)\.?\s*[A-Za-z0-9-]+)?(?:,\s*[A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,2})?(?:,?\s+[A-Z]{2}\b)?(?:,?\s+\d{5}(?:-\d{4})?\b)?/g,
  },
];

const LOCAL_NER_RULES: RedactionPatternRule[] = [
  {
    type: "PERSON_NAME",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b([A-Z][A-Za-z.'-]{1,30})\s+(?:from|near)\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\b/g,
    valueGroup: 1,
  },
  {
    type: "LOCATION",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b[A-Z][A-Za-z.'-]{1,30}\s+(?:from|near)\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\b/g,
    valueGroup: 1,
  },
  {
    type: "PERSON_NAME",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:friend|coworker|manager|doctor|lawyer|therapist|son|daughter|spouse|partner|roommate|client)\s+(?:named|called)?\s*([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,2})\b/g,
    valueGroup: 1,
  },
  {
    type: "LOCATION",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:moved to|staying in|grew up in|works in|goes to school in)\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\b/g,
    valueGroup: 1,
  },
  {
    type: "ORGANIZATION",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:I work at|I work for|my employer is|employed by|contracting for|client is)\s+([A-Z][A-Za-z0-9&.'-]*(?:\s+[A-Z][A-Za-z0-9&.'-]*){0,4})\b/g,
    valueGroup: 1,
  },
  {
    type: "SCHOOL",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:I go to|I attend|student at|my school is)\s+([A-Z][A-Za-z0-9&.'-]*(?:\s+[A-Z][A-Za-z0-9&.'-]*){0,5})\b/g,
    valueGroup: 1,
  },
  {
    type: "JOB_TITLE",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:job title is|role is|working as an?|I am an?|I(?:'|\u2019)m an?)\s+((?:[a-z]+(?:\s+|$)){0,4}(?:engineer|developer|designer|manager|analyst|nurse|teacher|lawyer|doctor|accountant|consultant|student|founder|marketer|writer|recruiter|therapist|assistant))\b/gi,
    valueGroup: 1,
    filter: (value) => value.trim().split(/\s+/).length <= 5,
  },
  {
    type: "DATE",
    confidence: "medium",
    source: "ner",
    pattern:
      /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:,\s*\d{4})?\b/gi,
  },
];

const CONTEXT_RULES: RedactionPatternRule[] = [
  {
    type: "SENSITIVE_CONTEXT",
    confidence: "medium",
    source: "context",
    pattern:
      /\bmy\s+(?:son|daughter|spouse|wife|husband|partner|roommate|child|kid|mother|father|parent)\b/gi,
  },
  {
    type: "SENSITIVE_CONTEXT",
    confidence: "medium",
    source: "context",
    pattern:
      /\b(?:diagnosed with|my diagnosis|therapist|medication|symptoms|doctor said|my doctor|psychiatrist)\b/gi,
  },
  {
    type: "SENSITIVE_CONTEXT",
    confidence: "medium",
    source: "context",
    pattern:
      /\b(?:case number|my lawyer|court date|immigration case|arrested|lawsuit|probation)\b/gi,
  },
  {
    type: "SENSITIVE_CONTEXT",
    confidence: "medium",
    source: "context",
    pattern:
      /\b(?:my manager|my employer|salary|performance review|paycheck|laid off)\b/gi,
  },
  {
    type: "SENSITIVE_CONTEXT",
    confidence: "medium",
    source: "context",
    pattern:
      /\b(?:tax return|bank balance|credit score|student ID|medical record|debt)\b/gi,
  },
];

const PAYMENT_CARD_PATTERN = /\b(?:\d[ -]*?){13,19}\b/g;
const REDACTION_TYPES = new Set<RedactionType>([
  "ADDRESS",
  "AGE",
  "BANK_ACCOUNT",
  "CONNECTION_URL",
  "CUSTOM_TERM",
  "DATE",
  "DOB",
  "EMAIL",
  "IP_ADDRESS",
  "JOB_TITLE",
  "LOCATION",
  "ORGANIZATION",
  "PAYMENT_CARD",
  "PERSON_NAME",
  "PHONE",
  "PRIVATE_KEY",
  "SCHOOL",
  "SECRET",
  "SENSITIVE_CONTEXT",
  "SSN",
  "TOKEN",
]);

export function redactSensitiveText(
  input: string,
  options: RedactionOptions = {},
  session: RedactionSession = createRedactionSession()
): RedactionResult {
  const state = session;
  const context: RedactionContext = {
    customTerms: normalizeCustomTerms(options.customTerms),
    decisions: options.decisions ?? {},
    privacyMode: options.privacyMode ?? "strict",
    sourceLocation: options.sourceLocation ?? "prompt",
    sourceLabel: options.sourceLabel,
    localNerSpans: options.localNerSpans ?? [],
  };
  const spans = resolveDetectionSpans(collectDetectionSpans(input, context));
  const text = replaceSpans(input, spans, state, context);

  return {
    text,
    changed: text !== input,
    counts: state.counts,
    entities: state.entities,
    placeholderMap: Array.from(state.placeholderMap.values()),
    spans,
  };
}

export function createRedactionSession(): RedactionSession {
  return {
    counts: {},
    entities: [],
    placeholderMap: new Map(),
    placeholderSeen: new Map(),
    seen: new Map(),
  };
}

export function redactionDefaultActionFor({
  confidence,
  privacyMode,
}: {
  confidence: RedactionConfidence;
  privacyMode: RedactionPolicyMode;
}): RedactionAction {
  if (privacyMode === "off") return "allow";
  if (privacyMode === "standard") return confidence === "high" ? "redact" : "allow";
  if (privacyMode === "strict") return confidence === "low" ? "allow" : "redact";
  return confidence === "low" ? "allow" : "redact";
}

function collectDetectionSpans(
  input: string,
  context: RedactionContext
): DetectionSpan[] {
  return [
    ...collectCustomTermSpans(input, context),
    ...collectPatternSpans(input, STRUCTURED_RULES, context),
    ...collectPaymentCardSpans(input, context),
    ...collectPatternSpans(input, LOCAL_NER_RULES, context),
    ...collectPatternSpans(input, CONTEXT_RULES, context),
    ...collectLocalNerSpans(input, context),
  ];
}

function collectLocalNerSpans(
  input: string,
  context: RedactionContext
): DetectionSpan[] {
  const spans: DetectionSpan[] = [];

  for (const span of context.localNerSpans) {
    if (
      !Number.isInteger(span.start) ||
      !Number.isInteger(span.end) ||
      span.start < 0 ||
      span.end > input.length ||
      span.end <= span.start
    ) {
      continue;
    }

    const value = input.slice(span.start, span.end);
    if (!value.trim()) continue;

    spans.push({
      type: span.type,
      start: span.start,
      end: span.end,
      value,
      confidence: span.confidence,
      source: "ner",
      sourceLocation: context.sourceLocation,
      sourceLabel: context.sourceLabel,
      retainOriginalValue: true,
    });
  }

  return spans;
}

function collectCustomTermSpans(
  input: string,
  context: RedactionContext
): DetectionSpan[] {
  const spans: DetectionSpan[] = [];

  for (const term of context.customTerms) {
    const pattern = new RegExp(escapeRegExp(term.value), "gi");
    for (const match of execAll(pattern, input)) {
      spans.push({
        type: term.type,
        start: match.index,
        end: match.index + match[0].length,
        value: match[0],
        confidence: "high",
        source: "custom",
        sourceLocation: context.sourceLocation,
        sourceLabel: context.sourceLabel,
        retainOriginalValue: true,
      });
    }
  }

  return spans;
}

function collectPatternSpans(
  input: string,
  rules: RedactionPatternRule[],
  context: RedactionContext
): DetectionSpan[] {
  const spans: DetectionSpan[] = [];

  for (const rule of rules) {
    for (const match of execAll(rule.pattern, input)) {
      const groupIndex = rule.valueGroup ?? 0;
      const matchedValue = String(match[groupIndex] ?? "");
      if (!matchedValue) continue;
      if (rule.filter && !rule.filter(matchedValue, match)) continue;

      const offset = groupIndex === 0 ? 0 : match[0].indexOf(matchedValue);
      if (offset < 0) continue;

      const value =
        typeof rule.valueForEntity === "function"
          ? rule.valueForEntity(matchedValue, match)
          : rule.valueForEntity ?? matchedValue;
      const start = match.index + offset;

      spans.push({
        type: rule.type,
        start,
        end: start + matchedValue.length,
        value,
        confidence: rule.confidence,
        source: rule.source ?? "regex",
        sourceLocation: context.sourceLocation,
        sourceLabel: context.sourceLabel,
        retainOriginalValue: rule.retainOriginalValue !== false,
      });
    }
  }

  return spans;
}

function collectPaymentCardSpans(
  input: string,
  context: RedactionContext
): DetectionSpan[] {
  const spans: DetectionSpan[] = [];

  for (const match of execAll(PAYMENT_CARD_PATTERN, input)) {
    const digits = match[0].replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19 || !passesLuhn(digits)) {
      continue;
    }

    spans.push({
      type: "PAYMENT_CARD",
      start: match.index,
      end: match.index + match[0].length,
      value: digits,
      confidence: "high",
      source: "regex",
      sourceLocation: context.sourceLocation,
      sourceLabel: context.sourceLabel,
      retainOriginalValue: true,
    });
  }

  return spans;
}

function resolveDetectionSpans(spans: DetectionSpan[]): DetectionSpan[] {
  const valid = spans.filter(
    (span) =>
      span.start >= 0 &&
      span.end > span.start &&
      span.value.trim().length > 0 &&
      Number.isFinite(span.start) &&
      Number.isFinite(span.end)
  );
  const ranked = [...valid].sort((a, b) => {
    const priority = spanPriority(b) - spanPriority(a);
    if (priority !== 0) return priority;

    const length = spanLength(b) - spanLength(a);
    if (length !== 0) return length;

    return a.start - b.start;
  });
  const accepted: DetectionSpan[] = [];

  for (const span of ranked) {
    if (accepted.some((current) => spansOverlap(current, span))) continue;
    accepted.push(span);
  }

  return accepted.sort((a, b) => a.start - b.start || a.end - b.end);
}

function replaceSpans(
  input: string,
  spans: DetectionSpan[],
  state: RedactionState,
  context: RedactionContext
): string {
  let text = "";
  let cursor = 0;

  for (const span of spans) {
    text += input.slice(cursor, span.start);
    text += replacementFor(span, input.slice(span.start, span.end), state, context);
    cursor = span.end;
  }

  text += input.slice(cursor);
  return text;
}

function replacementFor(
  span: DetectionSpan,
  originalText: string,
  state: RedactionState,
  context: RedactionContext
): string {
  const { entity, placeholderIndex } = entityFor(span, state, context);
  const decision = context.decisions[entity.id];
  const action = decision?.action ?? entity.defaultAction;
  const placeholder = normalizePlaceholder(
    decision?.placeholder,
    entity.placeholder
  );

  entity.action = action;
  entity.placeholder = placeholder;

  if (action === "allow") return originalText;

  // Credentials are redacted without being retained, so restoring a message
  // leaves the placeholder in place rather than substituting the secret back
  // in.
  if (span.retainOriginalValue) {
    state.placeholderMap.set(placeholder, {
      placeholder,
      originalValue: span.value,
      type: span.type,
    });
  }

  state.counts[span.type] = Math.max(
    state.counts[span.type] ?? 0,
    placeholderIndexFrom(placeholder) ?? placeholderIndex
  );

  return placeholder;
}

function entityFor(
  span: DetectionSpan,
  state: RedactionState,
  context: RedactionContext
): { entity: RedactionEntity; placeholderIndex: number } {
  const key = `${span.sourceLocation}:${span.type}:${span.value.toLowerCase()}`;
  const existing = state.seen.get(key);

  if (existing) {
    return {
      entity: existing.entity,
      placeholderIndex: existing.placeholderIndex,
    };
  }

  const placeholderKey = `${span.type}:${span.value.toLowerCase()}`;
  const seenPlaceholder = state.placeholderSeen.get(placeholderKey);
  const nextCount = seenPlaceholder?.placeholderIndex ?? (state.counts[span.type] ?? 0) + 1;
  const placeholder = seenPlaceholder?.placeholder ?? `[${span.type}_${nextCount}]`;
  const entity: RedactionEntity = {
    id: redactionEntityId(span.type, span.value, span.sourceLocation),
    type: span.type,
    originalValue: span.value,
    placeholder,
    confidence: span.confidence,
    source: span.source,
    sourceLocation: span.sourceLocation,
    sourceLabel: span.sourceLabel,
    defaultAction: redactionDefaultActionFor({
      confidence: span.confidence,
      privacyMode: context.privacyMode,
    }),
    action: "redact",
  };

  entity.action = entity.defaultAction;
  state.counts[span.type] = nextCount;
  state.placeholderSeen.set(placeholderKey, {
    placeholder,
    placeholderIndex: nextCount,
  });
  state.entities.push(entity);
  state.seen.set(key, {
    entity,
    placeholderIndex: nextCount,
  });

  return { entity, placeholderIndex: nextCount };
}

export function redactionEntityId(
  type: RedactionType,
  originalValue: string,
  sourceLocation: RedactionSourceLocation
): string {
  return `${sourceLocation}:${type}:${hashString(originalValue.toLowerCase())}`;
}

export function normalizePlaceholder(
  value: string | undefined,
  fallback: string
): string {
  if (!value) return fallback;

  const trimmed = value.trim();
  const inner = trimmed.startsWith("[") && trimmed.endsWith("]")
    ? trimmed.slice(1, -1)
    : trimmed;
  const normalized = inner
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "");

  if (!normalized) return fallback;
  return `[${normalized}]`;
}

function execAll(pattern: RegExp, input: string): RegExpExecArray[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const regex = new RegExp(pattern.source, flags);
  const matches: RegExpExecArray[] = [];
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    matches.push(match);
    if (match[0].length === 0) regex.lastIndex += 1;
  }

  return matches;
}

function spanPriority(span: DetectionSpan): number {
  return (
    sourcePriority(span.source) * 100 +
    confidencePriority(span.confidence) * 10 +
    Math.min(spanLength(span), 9)
  );
}

function sourcePriority(source: RedactionDetectorSource): number {
  switch (source) {
    case "custom":
      return 5;
    case "regex":
      return 4;
    case "context":
      return 3;
    case "ner":
      return 2;
    case "attachment":
      return 1;
  }
}

function confidencePriority(confidence: RedactionConfidence): number {
  switch (confidence) {
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
  }
}

function spanLength(span: DetectionSpan): number {
  return span.end - span.start;
}

function spansOverlap(a: DetectionSpan, b: DetectionSpan): boolean {
  return a.start < b.end && b.start < a.end;
}

function placeholderIndexFrom(placeholder: string): number | null {
  const match = placeholder.match(/_(\d+)\]$/);
  if (!match) return null;
  const value = Number.parseInt(match[1], 10);
  return Number.isFinite(value) ? value : null;
}

function passesLuhn(value: string): boolean {
  let sum = 0;
  let shouldDouble = false;

  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = Number(value[index]);

    if (!Number.isInteger(digit)) return false;

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum > 0 && sum % 10 === 0;
}

function isLikelyAge(value: string): boolean {
  const age = Number.parseInt(value, 10);
  return Number.isInteger(age) && age >= 0 && age <= 125;
}

function normalizeCustomTerms(
  terms: string[] | undefined
): NormalizedCustomTerm[] {
  if (!terms) return [];

  const seen = new Set<string>();
  const normalized: NormalizedCustomTerm[] = [];

  for (const term of terms) {
    const entry = parseCustomTerm(term);
    if (!entry) continue;

    const key = `${entry.type}:${entry.value.toLowerCase()}`;
    if (entry.value.length < 2 || seen.has(key)) continue;

    seen.add(key);
    normalized.push(entry);
  }

  return normalized;
}

function parseCustomTerm(term: string): NormalizedCustomTerm | null {
  const trimmed = term.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;

  const bracketed = trimmed.match(/^\[([A-Z_]+)\]\s+(.+)$/);
  if (bracketed) {
    return {
      type: isRedactionType(bracketed[1]) ? bracketed[1] : "CUSTOM_TERM",
      value: bracketed[2].trim(),
    };
  }

  const prefixed = trimmed.match(/^([A-Z_]+)\s*:\s*(.+)$/);
  if (prefixed && isRedactionType(prefixed[1])) {
    return {
      type: prefixed[1],
      value: prefixed[2].trim(),
    };
  }

  return {
    type: "CUSTOM_TERM",
    value: trimmed,
  };
}

function isRedactionType(value: string): value is RedactionType {
  return REDACTION_TYPES.has(value as RedactionType);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hashString(value: string): string {
  let hash = 5381;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 33) ^ value.charCodeAt(index);
  }

  return (hash >>> 0).toString(36);
}
