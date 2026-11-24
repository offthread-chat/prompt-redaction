import type {
  PlaceholderMapEntry,
  RedactionType,
} from "./promptRedaction.ts";

export type PrivacyMode = "strict" | "standard" | "manual" | "off";

export type RequestClass =
  | "standard_text"
  | "reasoning_text"
  | "web_search"
  | "file_attachment"
  | "pdf_or_image";

export type EntityCounts = Partial<Record<RedactionType, number>>;

export type AttachmentInspectionSummary = {
  inspectedCount: number;
  uninspectableCount: number;
  uninspectableFiles: string[];
};

export const DEFAULT_PRIVACY_MODE: PrivacyMode = "standard";

export const PRIVACY_MODE_OPTIONS: Array<{
  id: PrivacyMode;
  label: string;
  description: string;
}> = [
  {
    id: "standard",
    label: "Standard",
    description: "Replaces high-confidence detections. Lower-confidence ones are sent as written, so some names can get through.",
  },
  {
    id: "strict",
    label: "Strict",
    description: "Also replaces medium-confidence detections. Catches more names, and sometimes replaces harmless words.",
  },
  {
    id: "manual",
    label: "Manual",
    description: "Detects like Strict, then holds the send for your review when anything is found.",
  },
  {
    id: "off",
    label: "Off",
    description: "Sends your text as typed, without the on-device model. The server still applies its pattern rules.",
  },
];

const REDACTION_TYPE_LABELS: Record<RedactionType, string> = {
  ADDRESS: "Address",
  AGE: "Age",
  BANK_ACCOUNT: "Bank account",
  CONNECTION_URL: "Connection URL",
  CUSTOM_TERM: "Custom term",
  DATE: "Date",
  DOB: "Date of birth",
  EMAIL: "Email",
  IP_ADDRESS: "IP address",
  JOB_TITLE: "Job title",
  LOCATION: "Location",
  ORGANIZATION: "Organization",
  PAYMENT_CARD: "Payment card",
  PERSON_NAME: "Person name",
  PHONE: "Phone",
  PRIVATE_KEY: "Private key",
  SCHOOL: "School",
  SECRET: "Secret",
  SENSITIVE_CONTEXT: "Sensitive context",
  SSN: "SSN",
  TOKEN: "Token",
};

export function isPrivacyMode(value: unknown): value is PrivacyMode {
  return (
    value === "strict" ||
    value === "standard" ||
    value === "manual" ||
    value === "off"
  );
}

export function redactionTypeLabel(type: RedactionType): string {
  return REDACTION_TYPE_LABELS[type];
}

export function mergeEntityCounts(...counts: EntityCounts[]): EntityCounts {
  const merged: EntityCounts = {};

  for (const count of counts) {
    for (const [type, value] of Object.entries(count) as Array<
      [RedactionType, number]
    >) {
      if (!Number.isFinite(value) || value <= 0) continue;
      merged[type] = (merged[type] ?? 0) + value;
    }
  }

  return merged;
}

export function entityCountTotal(counts: EntityCounts): number {
  return Object.values(counts).reduce((total, value) => total + (value ?? 0), 0);
}

export function formatEntityCounts(counts: EntityCounts): string {
  const entries = (Object.entries(counts) as Array<[RedactionType, number]>)
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => redactionTypeLabel(a).localeCompare(redactionTypeLabel(b)));

  if (entries.length === 0) return "No detected entities";

  return entries
    .map(([type, count]) => `${redactionTypeLabel(type)} ${count}`)
    .join(", ");
}

export function restorePlaceholders(
  text: string,
  placeholderMap: PlaceholderMapEntry[]
): string {
  let restored = text;

  for (const entry of placeholderMap
    .filter((item) => item.placeholder && item.originalValue)
    .sort((a, b) => b.placeholder.length - a.placeholder.length)) {
    restored = restored.replaceAll(entry.placeholder, entry.originalValue);
  }

  return restored;
}

/**
 * Whether a web link carries a restored value. Restoring runs over the whole
 * reply, so a reply that echoes `?e=[EMAIL_1]` from a pasted document or a web
 * result would otherwise become a link holding the real address. A link that
 * is the restored value itself is fine: the user's own URL came back.
 */
export function linkCarriesRestoredValue(
  href: string,
  placeholderMap: PlaceholderMapEntry[]
): boolean {
  if (!/^https?:/i.test(href)) return false;

  const haystack = decodeEscapes(href).toLowerCase();
  return placeholderMap.some(({ originalValue }) => {
    const value = originalValue.toLowerCase();
    if (!value || value === haystack || /^https?:/.test(value)) return false;
    return containsWholeValue(haystack, value);
  });
}

/** Decodes each valid escape, so one bad one cannot hide the rest. */
function decodeEscapes(url: string): string {
  return url
    .replace(/\+/g, " ")
    .replace(/(?:%[0-9a-f]{2})+/gi, (escapes) => {
      try {
        return decodeURIComponent(escapes);
      } catch {
        return escapes;
      }
    });
}

/** "li" should not match inside "/library"; names in CJK have no such edges. */
function containsWholeValue(haystack: string, value: string): boolean {
  const isWordChar = (char: string | undefined) =>
    char !== undefined && /[a-z0-9]/.test(char);
  let index = haystack.indexOf(value);
  while (index !== -1) {
    const clearBefore = !isWordChar(value[0]) || !isWordChar(haystack[index - 1]);
    const clearAfter =
      !isWordChar(value[value.length - 1]) ||
      !isWordChar(haystack[index + value.length]);
    if (clearBefore && clearAfter) return true;
    index = haystack.indexOf(value, index + 1);
  }
  return false;
}

export function hasRestorablePlaceholders(
  text: string,
  placeholderMap: PlaceholderMapEntry[]
): boolean {
  return placeholderMap.some((entry) => text.includes(entry.placeholder));
}

export function mergePlaceholderMaps(
  current: PlaceholderMapEntry[],
  incoming: PlaceholderMapEntry[]
): PlaceholderMapEntry[] {
  const byPlaceholder = new Map<string, PlaceholderMapEntry>();

  for (const entry of current) {
    byPlaceholder.set(entry.placeholder, entry);
  }

  for (const entry of incoming) {
    byPlaceholder.set(entry.placeholder, entry);
  }

  return Array.from(byPlaceholder.values());
}

export function requestClassLabel(requestClass: RequestClass): string {
  switch (requestClass) {
    case "web_search":
      return "Web search";
    case "pdf_or_image":
      return "PDF or image";
    case "file_attachment":
      return "File attachment";
    case "reasoning_text":
      return "Reasoning prompt";
    case "standard_text":
      return "Text prompt";
  }
}
