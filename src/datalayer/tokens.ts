/** v0.4 §14.4 — the token a model reads in place of a value: `⟦EMAIL_1⟧`, `⟦PERSON_2.first⟧`, `⟦IBAN_1 · PT …4417⟧`. */

/** U+27E6 and U+27E7: rare enough in text that a token is not mistaken for content. */
export const TOKEN_OPEN = "⟦";
export const TOKEN_CLOSE = "⟧";

/** A token as written, read. */
export interface TokenFound {
  /** Where in the call's arguments it stands, as a path: `to`, `recipient.email`, `lines[].note`. */
  at: string;
  /** The token as written, hint included. */
  token: string;
  label: string;
  /** Its number in the conversation; absent on the mark of a removed value (`⟦SECRET⟧`, §14.3). */
  n?: number;
  part?: "first" | "last";
}

const TOKEN = new RegExp(`${TOKEN_OPEN}([^${TOKEN_OPEN}${TOKEN_CLOSE}]*)${TOKEN_CLOSE}`, "g");
const BODY = /^([A-Z][A-Z0-9_]*?)(?:_([1-9][0-9]*))?(?:\.(first|last))?$/;

/** §14.4 — one token's inside, read: the label, the number, the part. Null when it is not a token's form. */
function readToken(inside: string): Pick<TokenFound, "label" | "n" | "part"> | null {
  const body = inside.split(" · ")[0]!; // a hint follows ` · `, and filling ignores it
  const m = BODY.exec(body);
  if (!m) return null;
  return { label: m[1]!, ...(m[2] ? { n: Number(m[2]) } : {}), ...(m[3] ? { part: m[3] as "first" | "last" } : {}) };
}

/**
 * §14.5 — every token a call's arguments carry, in texts at any depth. Anything between the two brackets counts,
 * whatever its form: the layer escaped every bracket the model read (§14.4), so one that reaches a call was written
 * as a token, by the layer or by a model imitating one, and a call carrying either is refused.
 */
export function tokensIn(params: unknown, at = ""): TokenFound[] {
  if (typeof params === "string") {
    return [...params.matchAll(TOKEN)].map((m) => ({ at, token: m[0], ...(readToken(m[1]!) ?? { label: "" }) }));
  }
  if (Array.isArray(params)) return params.flatMap((item) => tokensIn(item, `${at}[]`));
  if (params && typeof params === "object") {
    return Object.entries(params).flatMap(([name, value]) => [...tokensIn(name, at), ...tokensIn(value, at ? `${at}.${name}` : name)]);
  }
  return [];
}

/**
 * §14.4 — what the layer does to text before replacing anything in it: every bracket becomes `[` or `]`, so every
 * token the model reads was put there by the layer and text from outside cannot forge one.
 */
export function escapeTokenBrackets(text: string): string {
  return text.replaceAll(TOKEN_OPEN, "[").replaceAll(TOKEN_CLOSE, "]");
}
