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
  /** v0.3 §0.6.1 — the tools whose calls the version governs. */
  tools?: string[];
  /** v0.3 §0.6.1 — those of `tools` no rule limits, on purpose. */
  unrestricted?: string[];
}

/**
 * Build an `ActionDetail` (ActionVersion content), generating each rule's CEL `expression` (N13).
 *
 * It builds drafts too — an imported action whose tools are listed and not yet decided — so it does
 * not hold a version to what may be PUBLISHED; {@link actionPublishIssues} does.
 */
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
    // An empty `unrestricted` is kept when `tools` is given: "none of them" is a statement, not an absence.
    ...(input.tools ? { tools: input.tools, unrestricted: input.unrestricted ?? [] } : {}),
  };
}

/**
 * v0.3 §0.6.1 — what stops an ActionVersion being published, in words; empty when it may be. The
 * issuer's check, run before a version is published, never at verify: a version already published is
 * read as written.
 *
 * - Every rule carries a `description`.
 * - With `tools`: each listed tool is governed by a rule (one whose `appliesTo` names it, or one with
 *   no `appliesTo`) or is in `unrestricted`, never both; `unrestricted`, every `appliesTo` and
 *   `stepUp.tools` name listed tools only. No rules at all is valid only when every tool is unrestricted.
 * - Without `tools`: at least one rule — one that constrains nothing is a permission, not a policy.
 */
export function actionPublishIssues(content: Pick<ActionDetail, "rules" | "tools" | "unrestricted" | "stepUp">): string[] {
  const issues: string[] = [];
  const rules = content.rules ?? [];
  for (const r of rules) {
    if (!r.description?.trim()) issues.push(`rule "${r.name}" has no description`);
  }
  if (!content.tools && rules.length === 0) issues.push("an action that lists no tools needs at least one rule");
  return [...issues, ...actionToolIssues(content)];
}

/**
 * v0.3 §0.6.1 — the tool-list half of {@link actionPublishIssues}: each listed tool limited by a rule or
 * unrestricted, never both, and no name outside `tools`. Empty for a version without `tools`. For an
 * issuer whose own checks already cover descriptions and "at least one rule".
 */
export function actionToolIssues(content: Pick<ActionDetail, "rules" | "tools" | "unrestricted" | "stepUp">): string[] {
  if (!content.tools) return [];
  const issues: string[] = [];
  const rules = content.rules ?? [];
  const tools = content.tools;
  if (tools.length === 0) issues.push("`tools` lists no tool");
  const listed = new Set(tools);
  if (listed.size !== tools.length) issues.push("`tools` lists a tool twice");
  const unrestricted = new Set(content.unrestricted ?? []);
  const outside = (where: string, names: Iterable<string>) => {
    for (const n of names) if (!listed.has(n)) issues.push(`${where} names "${n}", which \`tools\` does not list`);
  };
  outside("`unrestricted`", unrestricted);
  for (const r of rules) outside(`rule "${r.name}" (appliesTo)`, r.appliesTo ?? []);
  outside("`stepUp.tools`", content.stepUp?.tools ?? []);
  const governed = (tool: string) => rules.some((r) => !r.appliesTo?.length || r.appliesTo.includes(tool));
  for (const tool of tools) {
    const limited = governed(tool);
    if (limited && unrestricted.has(tool)) issues.push(`"${tool}" is both limited by a rule and marked unrestricted`);
    if (!limited && !unrestricted.has(tool)) issues.push(`"${tool}" is neither limited by a rule nor marked unrestricted`);
  }
  return issues;
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
