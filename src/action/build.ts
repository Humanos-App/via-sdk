import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { buildMapValueResolver, buildTypeResolver, expressionMismatches, generateCelExpression } from "./cel.js";
import { assertNoUnverifiedClientRefs } from "../agent/constraints.js";
import { constantsRead, readsUserParams } from "../cel/evaluate.js";
import { validateConstants } from "./execution-params.js";
import type { ActionDetail, ActionFor, ActionTarget, ConstantDef, ParamDef, RuleCondition } from "./types.js";

export interface BuildActionVersionInput {
  $id: string;
  type?: string;
  version: string;
  /** v0.3 §0.6.1 — a mandate's (the default) or a policy's. */
  for?: ActionFor;
  target?: ActionTarget;
  userParams?: Record<string, ParamDef>;
  /** v0.3 §0.6.1 — a policy action's own values, read by its rules as `constants.<name>`. */
  constants?: Record<string, ConstantDef>;
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
  const typeOf = buildTypeResolver({ userParams, executionParams, constants: input.constants });
  const valuesOf = buildMapValueResolver({ userParams, executionParams, constants: input.constants });
  const rules = (input.rules ?? []).map((r) => ({
    name: r.name,
    ...(r.description ? { description: r.description } : {}),
    // S13 — applicability travels with the rule. Dropping it here would publish an action whose
    // rules look unconditional and behave otherwise, which is the drift the fields exist to end.
    ...(r.appliesTo?.length ? { appliesTo: r.appliesTo } : {}),
    ...(r.requires?.length ? { requires: r.requires } : {}),
    conditions: r.conditions,
    expression: generateCelExpression(r.conditions, typeOf, valuesOf),
  }));
  // v0.3 §9.4ter(c): a rule MUST NOT read what a client says about itself, and an implementation MUST
  // refuse it when the action is written — the last moment its hollowness is visible.
  assertNoUnverifiedClientRefs(rules);
  return {
    $id: input.$id,
    type: input.type ?? "VIAAction",
    version: input.version,
    ...(input.for ? { for: input.for } : {}),
    ...(input.target ? { target: input.target } : {}),
    // A policy action has no userParams; one given anyway is kept, for actionPublishIssues to refuse.
    ...(input.for !== "policy" || input.userParams ? { userParams } : {}),
    ...(input.constants ? { constants: input.constants } : {}),
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
 * - Every rule carries a `description`, and a rule with `conditions` the expression they generate (§0.6.2).
 * - With `tools`: each listed tool is governed by a rule (one whose `appliesTo` names it, or one with
 *   no `appliesTo`) or is in `unrestricted`, never both; `unrestricted`, every `appliesTo` and
 *   `stepUp.tools` name listed tools only. No rules at all is valid only when every tool is unrestricted.
 * - Without `tools`: at least one rule — one that constrains nothing is a permission, not a policy.
 * - By what it is for ({@link actionForIssues}): `mandate` or `policy`, and a policy action neither declares nor reads
 *   userParams; each constant has a value of its type; every constant a rule reads is declared.
 */
export function actionPublishIssues(
  content: Pick<ActionDetail, "rules" | "tools" | "unrestricted" | "stepUp" | "for" | "userParams" | "constants"> &
    Partial<Pick<ActionDetail, "executionParams">>,
): string[] {
  const issues: string[] = [];
  const rules = content.rules ?? [];
  for (const r of rules) {
    if (!r.description?.trim()) issues.push(`Describe rule "${r.name}" in a sentence: it is the reason a denied call gives.`);
  }
  for (const name of expressionMismatches(content)) {
    issues.push(`Regenerate rule "${name}" from its conditions: its expression is not what they generate. To keep the expression as written, remove its conditions.`);
  }
  if (!content.tools && rules.length === 0) issues.push("Add at least one rule: an action that covers no tools needs one.");
  return [...issues, ...actionToolIssues(content), ...actionForIssues(content)];
}

/** A constant's name, read as `constants.<name>`: a CEL identifier. */
const CONSTANT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * v0.3 §0.6.1 — the half of {@link actionPublishIssues} that follows what the version is for, and its constants. `for`
 * is `mandate` or `policy`. A policy runs its rules with no person's values (§21.3), so a policy action neither declares
 * nor reads userParams, and fixes its limits as constants. Any version may declare constants; each is named so a rule
 * can read it and carries a value of its type, and every `constants.<name>` a rule reads, in a condition or its CEL, is
 * one the version declares: an undeclared one errors on every call, which is a deny.
 */
export function actionForIssues(content: Pick<ActionDetail, "rules" | "for" | "userParams" | "constants">): string[] {
  const issues: string[] = [];
  const constants = content.constants ?? {};
  const declared = Object.keys(constants);
  if (content.for !== undefined && content.for !== "mandate" && content.for !== "policy") {
    issues.push(`"for" is "${String(content.for)}": it must be mandate or policy.`);
  }
  if (content.for === "policy") {
    const userParams = Object.keys(content.userParams ?? {});
    if (userParams.length)
      issues.push(`A policy action has no user params (${userParams.join(", ")}): a policy runs with no person to set them. Make each one a constant.`);
    for (const r of content.rules ?? []) {
      if (ruleReadsUserParams(r)) issues.push(`Rule "${r.name}" reads userParams, which a policy action has none of. Read a constant instead.`);
    }
  }
  for (const name of declared) {
    if (!CONSTANT_NAME.test(name)) issues.push(`Rename constant "${name}": use only letters, digits and _, not starting with a digit, so a rule can read it.`);
  }
  try {
    validateConstants(content);
  } catch (e) {
    issues.push((e as Error).message);
  }
  for (const r of content.rules ?? []) {
    const fromConditions = (r.conditions ?? []).flatMap((c) =>
      [c.left, c.right, c.leftKey, c.rightKey].flatMap((ref) => (ref?.startsWith("constants.") ? [ref.slice("constants.".length)] : [])),
    );
    const read = new Set([...fromConditions, ...(constantsRead(r.expression ?? "") ?? [])]);
    const missing = [...read].filter((name) => !Object.hasOwn(constants, name));
    if (missing.length)
      issues.push(`Rule "${r.name}" reads ${missing.map((n) => `constants.${n}`).join(", ")}, which this version does not declare. Add it, or change the rule.`);
  }
  return issues;
}

/**
 * v0.3 §16.4 — may a guardrail mandate pin this version? Not one written for the organization's policy; one without
 * `for`, written before it, may.
 */
export function mandateMayPin(content: Pick<ActionDetail, "for">): boolean {
  return content.for !== "policy";
}

/**
 * v0.3 §21.1 — may the organization's policy name this version, as its `everyCall` or a `rules` entry's action? Not
 * one written for a mandate. One without `for`, written before it, may when it declares no userParams and no rule of
 * it reads one: the policy runs it with none, so such a rule would error on every call.
 */
export function policyMayName(content: Pick<ActionDetail, "for" | "userParams" | "rules">): boolean {
  if (content.for === "mandate") return false;
  if (Object.keys(content.userParams ?? {}).length) return false;
  return !(content.rules ?? []).some(ruleReadsUserParams);
}

/** Does a rule read `userParams` — in a condition's operand or key, or in its expression's parse tree? */
function ruleReadsUserParams(rule: Pick<ActionDetail["rules"][number], "conditions" | "expression">): boolean {
  const refs = (rule.conditions ?? []).flatMap((c) => [c.left, c.right, c.leftKey, c.rightKey]);
  if (refs.some((ref) => ref?.startsWith("userParams."))) return true;
  const expression = rule.expression ?? "";
  // An expression that does not parse is read by its text: a rule that errors anyway is not worth the doubt.
  return readsUserParams(expression) ?? /\buserParams\b/.test(expression);
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
  if (tools.length === 0) issues.push("The action covers no tools: list at least one.");
  const listed = new Set(tools);
  if (listed.size !== tools.length) issues.push("The action lists a tool twice.");
  const unrestricted = new Set(content.unrestricted ?? []);
  const outside = (what: (n: string) => string, names: Iterable<string>) => {
    for (const n of names) if (!listed.has(n)) issues.push(`${what(n)}, but the action does not cover it.`);
  };
  outside((n) => `"${n}" is marked as needing no limits`, unrestricted);
  for (const r of rules) outside((n) => `Rule "${r.name}" applies to "${n}"`, r.appliesTo ?? []);
  outside((n) => `"${n}" needs human approval`, content.stepUp?.tools ?? []);
  const governed = (tool: string) => rules.some((r) => !r.appliesTo?.length || r.appliesTo.includes(tool));
  for (const tool of tools) {
    const limited = governed(tool);
    if (limited && unrestricted.has(tool)) issues.push(`"${tool}" has a rule and is marked as needing no limits: keep one.`);
    if (!limited && !unrestricted.has(tool)) issues.push(`Add a rule for "${tool}".`);
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
