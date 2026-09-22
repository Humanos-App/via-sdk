// §20 — the mandate description: the words the person was shown, their author, and which
// machinery governs them. Pure; the ceremony that collects an edit is the platform's (M7).
import type {
  Enforcement,
  Mandate,
  MandateDescription,
  ViaMandateCredential,
} from "../types.js";

/**
 * §20.1 MUST 2 — the length bound, in characters.
 *
 * Chosen against the READER, not against a database column. `semantic` enforcement hands these
 * words to a model, and the attack the bound exists for is `scope_creep_by_enumeration`: write
 * more than the reader holds, so the decisive clause falls off the end while the signature stays
 * valid. A reviewer that reads ~131 tokens comfortably is roughly 500 characters of English, so
 * the bound sits there rather than at a number that merely feels tidy. Raise it only together
 * with a reader that demonstrably holds more.
 */
export const DESCRIPTION_MAX_LENGTH = 500;

/** A reason a description is refused. Refusal happens at ISSUANCE — never truncation at read. */
export type DescriptionProblem =
  | "description_empty"
  | "description_too_long"
  | "description_lang_missing"
  | "description_author_invalid"
  | "description_required"
  | "description_author_not_issuer";

const AUTHORS = new Set(["issuer", "agent", "grantor"]);

/**
 * Validate one description object (§20.1). Shape only — whether it is ALLOWED on this mandate is
 * {@link validateMandateDescription}, which needs the enforcement mode to answer.
 */
export function validateDescription(d: MandateDescription | undefined): { ok: true } | { ok: false; reason: DescriptionProblem } {
  if (!d || typeof d.text !== "string" || d.text.trim() === "") return { ok: false, reason: "description_empty" };
  if (d.text.length > DESCRIPTION_MAX_LENGTH) return { ok: false, reason: "description_too_long" };
  if (typeof d.lang !== "string" || d.lang.trim() === "") return { ok: false, reason: "description_lang_missing" };
  if (!AUTHORS.has(d.author)) return { ok: false, reason: "description_author_invalid" };
  return { ok: true };
}

/**
 * §20.3 — the two validity rules, which only make sense together:
 *
 *   - a `semantic` or `none` mandate with NO description is a grant whose content is missing —
 *     which is exactly what a plain authorization becomes today when its evidence cannot be
 *     fetched;
 *   - a `rules` mandate whose description was not derived by the issuer is prose written beside
 *     rules that actually govern, and prose beside rules drifts from them.
 */
export function validateMandateDescription(
  mandate: Mandate,
): { ok: true } | { ok: false; reason: DescriptionProblem } {
  const enforcement = enforcementOf(mandate);
  const d = mandate.description;
  if (!d) {
    // A pre-§20 `rules` mandate carries no description and must keep verifying (v0.2-new §13);
    // the requirement bites where the description IS the grant.
    return enforcement === "rules" ? { ok: true } : { ok: false, reason: "description_required" };
  }
  const shape = validateDescription(d);
  if (!shape.ok) return shape;
  if (enforcement === "rules" && d.author !== "issuer") {
    return { ok: false, reason: "description_author_not_issuer" };
  }
  return { ok: true };
}

/**
 * §20.3 — the mandate's enforcement, DERIVED when the field is absent.
 *
 * Deriving is for artifacts issued before §20 existed: an action means its CEL governs, no action
 * means nothing does. It is deliberately NOT how a v0.3 mandate answers the question — that is the
 * field, because "no rules ran" and "rules ran and matched nothing" are different promises and an
 * absence cannot tell them apart.
 */
export function enforcementOf(mandate: Mandate): Enforcement {
  return mandate.enforcement ?? (mandate.action ? "rules" : "none");
}

/** The description of a mandate credential, if it carries one. */
export function descriptionOf(credential: ViaMandateCredential): MandateDescription | undefined {
  return credential.credentialSubject?.mandate?.description;
}

export interface AdoptInput {
  /** What the requester proposed. */
  draft: { text: string; lang: string };
  /** The agent that drafted it (§16.14). */
  proposedBy: string;
  /** What the grantor had in front of them when they decided. */
  accepted: string;
}

/**
 * §20.2 — the adoption bar.
 *
 * A click is consent to a grant; it is NOT authorship of a sentence. So text the grantor accepted
 * unchanged stays the AGENT's (`author: "agent"`, `adopted: true`), and becomes the grantor's only
 * when they edited it. The difference is what §20.2's narrowing rule keys on: agent-authored words
 * may deny or escalate a call, never allow one.
 *
 * Comparison is on trimmed text: leading whitespace is not an edit, and treating it as one would
 * let a UI hand an agent grantor-authorship for free.
 */
export function adoptDescription(input: AdoptInput): MandateDescription {
  const edited = input.accepted.trim() !== input.draft.text.trim();
  return {
    text: input.accepted.trim(),
    lang: input.draft.lang,
    author: edited ? "grantor" : "agent",
    proposedBy: { actor: input.proposedBy, adopted: true },
  };
}

/**
 * §20.2's narrowing rule, as a predicate: may a reader ACT on these words to widen what the agent
 * may do? Only when a party other than the requester wrote them.
 *
 * The reader — §20.6's reviewer, a consent card, an RP — may always act on them to narrow: deny a
 * call, or escalate it. This answers the other direction, and it is the whole reason `author` is a
 * required field rather than a nice-to-have.
 */
export function mayWidenAuthority(d: MandateDescription | undefined): boolean {
  return d?.author === "grantor" || d?.author === "issuer";
}
