import type { ActionDetail, ActionRule, ConditionOperator, ParamDef, ParamType, RuleCondition } from "./types.js";

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

/**
 * Resolve a reference like `userParams.maxAmount` / `executionParams.amount` / `constants.cap` (v0.3 §0.6.2) to its
 * declared type.
 */
export function buildTypeResolver(content: Pick<ActionDetail, "userParams" | "executionParams" | "constants">) {
  return (ref: string): ParamType | undefined => declaredAt(content, ref)?.type;
}

/** Resolve a `map` ref to its declared `values` type — the effective type once indexed. */
export function buildMapValueResolver(content: Pick<ActionDetail, "userParams" | "executionParams" | "constants">) {
  return (ref: string): ParamType | undefined => declaredAt(content, ref)?.values;
}

/** The declaration a `<scope>.<name>` ref names: a param, or a constant. */
function declaredAt(
  content: Pick<ActionDetail, "userParams" | "executionParams" | "constants">,
  ref: string,
): Pick<ParamDef, "type" | "values"> | undefined {
  const [scope, name] = ref.split(".", 2);
  if (!name) return undefined;
  if (scope === "userParams") return content.userParams?.[name];
  if (scope === "executionParams") return content.executionParams[name];
  if (scope === "constants") return content.constants?.[name];
  return undefined;
}

function wrapIfDatetime(ref: string, type: ParamType | undefined): string {
  return type === "datetime" ? `timestamp(${ref})` : ref;
}

/** The scopes an operand names (v0.3 §0.6.2). */
const SCOPES: ReadonlySet<string> = new Set(["userParams", "executionParams", "constants"]);
const CEL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** CEL's words: a name after a dot may not be one. */
const CEL_WORDS: ReadonlySet<string> = new Set(["true", "false", "null", "in"]);

/**
 * v0.3 §0.6.2 — `scope.name` as CEL reads it: dotted for an identifier, `scope["name"]` for a name that is not one or is
 * one of CEL's words. An executionParam keeps its tool input's name, and `executionParams.max-amount` would read as a
 * subtraction. Every other name is returned as given, so no expression generated before changes.
 */
export function celRef(ref: string): string {
  const dot = ref.indexOf(".");
  if (dot < 0) return ref;
  const scope = ref.slice(0, dot);
  const name = ref.slice(dot + 1);
  if (!SCOPES.has(scope) || (CEL_IDENTIFIER.test(name) && !CEL_WORDS.has(name))) return ref;
  return `${scope}[${JSON.stringify(name)}]`;
}

/** `userParams.caps` on its own, or `userParams.caps[executionParams.instrument]` when indexed. */
function operandRef(ref: string, key: string | undefined): string {
  return key ? `${celRef(ref)}[${celRef(key)}]` : celRef(ref);
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
  if (c.leftKey) guards.push(`${celRef(c.leftKey)} in ${celRef(c.left)}`);
  if (c.rightKey) guards.push(`${celRef(c.rightKey)} in ${celRef(c.right)}`);
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

/**
 * v0.3 §0.6.2 — the rules with `conditions` whose `expression` is not what those conditions generate, by name. An issuer
 * refuses them: a verifier runs the expression while an editor shows the conditions. A rule with none is written by hand.
 */
export function expressionMismatches(
  content: Pick<ActionDetail, "userParams" | "constants"> & {
    rules?: Pick<ActionRule, "name" | "conditions" | "expression">[];
    executionParams?: ActionDetail["executionParams"];
  },
): string[] {
  const declared = { ...content, executionParams: content.executionParams ?? {} };
  const typeOf = buildTypeResolver(declared);
  const valuesOf = buildMapValueResolver(declared);
  return (content.rules ?? [])
    .filter((r) => r.conditions?.length && r.expression !== generateCelExpression(r.conditions, typeOf, valuesOf))
    .map((r) => r.name);
}
