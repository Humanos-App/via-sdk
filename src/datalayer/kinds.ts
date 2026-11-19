/**
 * v0.4 §14 — the context layer's protocol parts: the kinds of personal data, the token a model reads in place of a
 * value, the policy's `context` and a tool's `fill`, and a call's `context`. Finding the data, keeping the values
 * and filling them are product (agent-sdk and the platform); what is here is what a policy says and a verifier
 * checks.
 */

/** §14.1 — the kinds, each with the label its token carries. `org.<name>` is an organization's own (§14.3). */
export const KIND_LABELS: Readonly<Record<string, string>> = {
  "person.name": "PERSON",
  "person.email": "EMAIL",
  "person.phone": "PHONE",
  "person.address": "ADDRESS",
  "person.national_id": "ID",
  "person.birth_date": "BIRTHDATE",
  "financial.iban": "IBAN",
  "financial.card": "CARD",
  "network.ip": "IP",
  "secret.key": "SECRET",
  "secret.private_key": "SECRET",
  "secret.password": "SECRET",
};

/** §14.1 — the hints a policy may show beside a token, by kind. */
export const KIND_HINTS: Readonly<Record<string, readonly string[]>> = {
  "person.email": ["domain"],
  "person.phone": ["country"],
  "person.address": ["city", "country"],
  "person.national_id": ["country", "type"],
  "person.birth_date": ["age band"],
  "financial.iban": ["country", "last4"],
  "financial.card": ["brand", "last4"],
};

const ORG_KIND = /^org\.[a-z][a-z0-9_]*$/;
const FAMILY = /^[a-z]+\.\*$/;

/** Is this one of §14.1's kinds, or an organization's own (`org.customer_number`)? */
export const isKind = (kind: unknown): kind is string => typeof kind === "string" && (kind in KIND_LABELS || ORG_KIND.test(kind));

/** Is this a kind or a family of them (`person.*`), as `tokens`, `remove` and `fill` name them? */
export const isKindOrFamily = (name: unknown): name is string => isKind(name) || (typeof name === "string" && FAMILY.test(name));

/** §14.1 — does a name a policy wrote cover this kind: the kind itself, or its family? */
export function coversKind(name: string, kind: string): boolean {
  return name === kind || (name.endsWith(".*") && kind.startsWith(name.slice(0, -1)));
}

/** §14.1, §14.4 — the label a kind's token carries: an organization's own is its name in capitals. */
export function labelOf(kind: string): string | null {
  if (kind in KIND_LABELS) return KIND_LABELS[kind]!;
  return ORG_KIND.test(kind) ? kind.slice(4).toUpperCase() : null;
}

/**
 * §14.4 — the kinds a label may stand for, among the fixed ones and the organization's own: one for most, the three
 * `secret.*` for `SECRET`, none for a label nobody defined.
 */
export function kindsOfLabel(label: string, orgKinds: readonly string[] = []): string[] {
  return [...Object.keys(KIND_LABELS), ...orgKinds.filter((k) => ORG_KIND.test(k))].filter((kind) => labelOf(kind) === label);
}
