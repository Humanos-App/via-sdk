import type { ActionDetail, ConditionOperator, ParamType, RuleCondition } from "./types.js";

/** Operators allowed per parameter type (matches the platform authoring UI). */
export const operatorsByType: Record<ParamType, ConditionOperator[]> = {
  string: ["==", "!=", "in", "not_in"],
  number: ["==", "!=", ">", "<", ">=", "<=", "in", "not_in"],
  integer: ["==", "!=", ">", "<", ">=", "<=", "in", "not_in"],
  boolean: ["==", "!="],
  datetime: ["==", "!=", ">", "<", ">=", "<="],
  array: ["==", "!="],
};

/** Resolve a reference like `userParams.maxAmount` / `executionParams.amount` to its declared type. */
export function buildTypeResolver(content: Pick<ActionDetail, "userParams" | "executionParams">) {
  return (ref: string): ParamType | undefined => {
    const [scope, name] = ref.split(".", 2);
    if (!name) return undefined;
    if (scope === "userParams") return content.userParams[name]?.type;
    if (scope === "executionParams") return content.executionParams[name]?.type;
    return undefined;
  };
}

function wrapIfDatetime(ref: string, type: ParamType | undefined): string {
  return type === "datetime" ? `timestamp(${ref})` : ref;
}

function conditionToCel(c: RuleCondition, typeOf: (ref: string) => ParamType | undefined): string {
  const left = wrapIfDatetime(c.left, typeOf(c.left));
  const right = wrapIfDatetime(c.right, typeOf(c.right));
  switch (c.operator) {
    case "in":
      return `${left} in ${c.right}`;
    case "not_in":
      return `!(${left} in ${c.right})`;
    default:
      return `${left} ${c.operator} ${right}`;
  }
}

/**
 * Generate the CEL expression for a rule from its `conditions` (N13 — normative).
 * Conditions OR-join; cross-rule logic is AND (every rule must pass). Ported
 * verbatim from the platform so the digest-pinned `expression` is byte-identical.
 */
export function generateCelExpression(
  conditions: RuleCondition[],
  typeOf: (ref: string) => ParamType | undefined,
): string {
  if (conditions.length === 0) return "";
  return conditions.map((c) => conditionToCel(c, typeOf)).join(" || ");
}
