import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { buildTypeResolver, generateCelExpression } from "./cel.js";
import { assertNoUnverifiedClientRefs } from "../agent/constraints.js";
import type { ActionDetail, ActionTarget, ParamDef, RuleCondition } from "./types.js";

export interface BuildActionVersionInput {
  $id: string;
  type?: string;
  version: string;
  target?: ActionTarget;
  userParams?: Record<string, ParamDef>;
  executionParams?: Record<string, ParamDef>;
  rules?: {
    name: string;
    description?: string;
    conditions: RuleCondition[];
    /** S13 — the tools this rule governs; absent ⇒ every call (see {@link ActionRule.appliesTo}). */
    appliesTo?: string[];
    /** S13 — parameters a governed call MUST carry, or it is denied `required_param_missing`. */
    requires?: string[];
  }[];
  mapper?: Record<string, string>;
  /** v0.3 §17.4 — the tools whose calls need the grantor's fresh co-sign. */
  stepUp?: { tools: string[] };
}

/** Build an `ActionDetail` (ActionVersion content), generating each rule's CEL `expression` (N13). */
export function buildActionVersion(input: BuildActionVersionInput): ActionDetail {
  const userParams = input.userParams ?? {};
  const executionParams = input.executionParams ?? {};
  const typeOf = buildTypeResolver({ userParams, executionParams });
  const rules = (input.rules ?? []).map((r) => ({
    name: r.name,
    ...(r.description ? { description: r.description } : {}),
    // S13 — applicability travels with the rule. Dropping it here would publish an action whose
    // rules look unconditional and behave otherwise, which is the drift the fields exist to end.
    ...(r.appliesTo?.length ? { appliesTo: r.appliesTo } : {}),
    ...(r.requires?.length ? { requires: r.requires } : {}),
    conditions: r.conditions,
    expression: generateCelExpression(r.conditions, typeOf),
  }));
  // v0.3 §9.4ter(c): a rule MUST NOT read what a client says about itself, and an implementation MUST
  // refuse it when the action is written — the last moment its hollowness is visible.
  assertNoUnverifiedClientRefs(rules);
  return {
    $id: input.$id,
    type: input.type ?? "VIAAction",
    version: input.version,
    ...(input.target ? { target: input.target } : {}),
    userParams,
    executionParams,
    rules,
    ...(input.mapper ? { mapper: input.mapper } : {}),
    ...(input.stepUp?.tools.length ? { stepUp: { tools: input.stepUp.tools } } : {}),
  };
}

/**
 * SRI digest pinning an ActionVersion's content into a mandate's `action` reference:
 * the RFC-8785 (JCS) canonical form + standard base64, so the digest is stable
 * regardless of key order.
 *
 * NOT the same value as the `ActionVersion.digestSRI` column the action API serves —
 * that one is `actionVersionPinSRI` (plain `JSON.stringify`, base64url), kept byte-stable
 * for consumers that already hold it. Two digests, two purposes; see `crypto/digest.ts`.
 */
export function actionDigestSRI(content: ActionDetail): string {
  return computeSRI(canonicalizeRFC8785(content));
}

/** Build the credential's `mandate.action` reference (`{ id, digestSRI, location }`). */
export function buildActionReference(
  content: ActionDetail,
  location: string,
): { id: string; digestSRI: string; location: string } {
  return { id: content.$id, digestSRI: actionDigestSRI(content), location };
}

/** Verify an ActionVersion matches a pinned reference (id + digest). */
export function verifyActionReference(
  content: ActionDetail,
  ref: { id: string; digestSRI: string },
): boolean {
  return content.$id === ref.id && actionDigestSRI(content) === ref.digestSRI;
}
