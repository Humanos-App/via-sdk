import type { ActionDetail, ConditionOperator, ParamType, RuleCondition } from "./types.js";

/** Operators allowed per parameter type (matches the platform authoring UI). */
export const operatorsByType: Record<ParamType, ConditionOperator[]> = {
  string: ["==", "!=", "in", "not_in"],
  number: ["==", "!=", ">", "<", ">=", "<=", "in", "not_in"],
  integer: ["==", "!=", ">", "<", ">=", "<=", "in", "not_in"],
  boolean: ["==", "!="],
  datetime: ["==", "!=", ">", "<", ">=", "<="],
  array: ["==", "!="],
  // A map as the LEFT operand only supports equality. The operator that matters for maps is
  // `in` with the map on the RIGHT (key membership), which is reached via the left operand's
  // own type — `string` already carries `in`.
  map: ["==", "!="],
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

/** Resolve a `map` ref to its declared `values` type — the effective type once indexed. */
export function buildMapValueResolver(content: Pick<ActionDetail, "userParams" | "executionParams">) {
  return (ref: string): ParamType | undefined => {
    const [scope, name] = ref.split(".", 2);
    if (!name) return undefined;
    if (scope === "userParams") return content.userParams[name]?.values;
    if (scope === "executionParams") return content.executionParams[name]?.values;
    return undefined;
  };
}

function wrapIfDatetime(ref: string, type: ParamType | undefined): string {
  return type === "datetime" ? `timestamp(${ref})` : ref;
}

/** `userParams.caps` on its own, or `userParams.caps[executionParams.instrument]` when indexed. */
function operandRef(ref: string, key: string | undefined): string {
  return key ? `${ref}[${key}]` : ref;
}

function conditionToCel(
  c: RuleCondition,
  typeOf: (ref: string) => ParamType | undefined,
  valuesOf?: (ref: string) => ParamType | undefined,
): { expression: string; guarded: boolean } {
  // An indexed operand's effective type is the map's value type, not `map`.
  const leftType = c.leftKey ? valuesOf?.(c.left) : typeOf(c.left);
  const rightType = c.rightKey ? valuesOf?.(c.right) : typeOf(c.right);
  const leftRef = operandRef(c.left, c.leftKey);
  const rightRef = operandRef(c.right, c.rightKey);
  const left = wrapIfDatetime(leftRef, leftType);
  const right = wrapIfDatetime(rightRef, rightType);

  let comparison: string;
  switch (c.operator) {
    case "in":
      comparison = `${left} in ${rightRef}`;
      break;
    case "not_in":
      comparison = `!(${left} in ${rightRef})`;
      break;
    default:
      comparison = `${left} ${c.operator} ${right}`;
  }

  // Every map index is guarded by its own membership test. Reading an absent key throws,
  // which the evaluator reports as an `error` carrying an engine message instead of a `fail`
  // carrying the rule's description — and rule descriptions are the reason codes an
  // integrator maps back to their own vocabulary. `&&` short-circuits, so a guarded index is
  // never reached for a key the map does not hold, and the rule simply fails.
  const guards: string[] = [];
  if (c.leftKey) guards.push(`${c.leftKey} in ${c.left}`);
  if (c.rightKey) guards.push(`${c.rightKey} in ${c.right}`);
  if (guards.length === 0) return { expression: comparison, guarded: false };
  return { expression: `${guards.join(" && ")} && ${comparison}`, guarded: true };
}

/**
 * Generate the CEL expression for a rule from its `conditions` (N13 — normative).
 * Conditions OR-join; cross-rule logic is AND (every rule must pass). Ported
 * verbatim from the platform so the digest-pinned `expression` is byte-identical.
 */
export function generateCelExpression(
  conditions: RuleCondition[],
  typeOf: (ref: string) => ParamType | undefined,
  valuesOf?: (ref: string) => ParamType | undefined,
): string {
  if (conditions.length === 0) return "";
  const parts = conditions.map((c) => conditionToCel(c, typeOf, valuesOf));
  if (parts.length === 1) return parts[0]!.expression;
  // `&&` already binds tighter than `||`, so the parentheses change nothing semantically.
  // They are here so a guarded condition reads as one unit next to its siblings — and only
  // guarded parts get them, which keeps every pre-existing expression byte-identical.
  return parts.map((p) => (p.guarded ? `(${p.expression})` : p.expression)).join(" || ");
}
