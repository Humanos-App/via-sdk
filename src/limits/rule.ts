/**
 * v0.4 §15.4 — a rule: its conditions, the CEL generated from them, and what stops one being signed.
 *
 * The expression is all a verifier runs, so everything a condition means is written into it. An input the call
 * leaves out makes its condition FALSE, never an error and never a skip: each generated condition first tests that
 * the value is there (`"amount" in params && …`), after the tool's declared defaults were filled in
 * (`inputsWithDefaults`). So a rule on `currency` cannot be passed by leaving `currency` out, and an exception
 * joined by OR still decides when the other side is absent.
 */
import { DECIMAL_PATTERN, evaluateCel } from "../cel/evaluate.js";
import { inputAt, parseInputPath, type InputKind } from "./tool.js";
import type { JsonSchema, LimitCondition, LimitEvaluation, LimitOperator, LimitRule } from "./types.js";

/** What a rule's condition may read besides the tool's inputs (§15.4). An input is written bare. */
export const RULE_SCOPES = ["agent", "accreditation", "context", "checks"] as const;
export type RuleScope = (typeof RULE_SCOPES)[number];

/** Where a rule is written: it decides how its conditions join and what they may read. */
export interface RulePlace {
  /** A policy's or an app's rule joins its conditions by OR; a mandate's has one condition. */
  document: "policy" | "app" | "mandate";
  /** The tool's input schema; absent for a root rule, which reads only `agent.*` and `accreditation.*`. */
  inputs?: JsonSchema;
  root: boolean;
}

const COMPARISONS: readonly LimitOperator[] = ["==", "!=", "<", "<=", ">", ">="];
const ORDERINGS: readonly LimitOperator[] = ["<", "<=", ">", ">="];
const TEXT_TESTS: Partial<Record<LimitOperator, string>> = {
  starts_with: "startsWith",
  ends_with: "endsWith",
  contains: "contains",
  every_starts_with: "startsWith",
  every_ends_with: "endsWith",
  every_contains: "contains",
};
const ITEM_OPERATORS: readonly LimitOperator[] = ["every_in", "none_in", "includes_all"];
const ITEM_TEXT_OPERATORS: readonly LimitOperator[] = ["every_starts_with", "every_ends_with", "every_contains"];

/** §15.4 — the operators an input of each kind takes. A list's are on its items; an object takes none. */
export const OPERATORS_BY_KIND: Record<InputKind, readonly LimitOperator[]> = {
  number: [...COMPARISONS, "in", "not_in"],
  integer: [...COMPARISONS, "in", "not_in"],
  decimal: [...COMPARISONS, "in", "not_in"],
  text: ["==", "!=", "in", "not_in", "starts_with", "ends_with", "contains"],
  datetime: ORDERINGS,
  boolean: ["=="],
  list: [...ITEM_OPERATORS, ...ITEM_TEXT_OPERATORS],
  object: [],
  unknown: [],
};
/** What `agent.*`, `accreditation.*`, `context.*` and `checks.*` take: their kinds are not declared to a rule. */
const SCOPED_OPERATORS: readonly LimitOperator[] = [...COMPARISONS, "in", "not_in"];

const CEL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CEL_WORDS: ReadonlySet<string> = new Set(["true", "false", "null", "in"]);

/** `base.name`, or `base["name"]` for a name CEL would not read as one. */
const member = (base: string, name: string) => (CEL_IDENTIFIER.test(name) && !CEL_WORDS.has(name) ? `${base}.${name}` : `${base}[${JSON.stringify(name)}]`);

/** A condition's `left`, read: the scope and the path inside it. */
export interface LeftOperand {
  scope: "params" | RuleScope;
  /** For `checks`: the capability, whose name holds dots (`order.get`). */
  capability?: string;
  path: string;
}

/**
 * §15.4 — read a `left` (or a `right`). `agent.`, `accreditation.`, `context.` and `checks.` name those; anything
 * else is one of the tool's inputs. `checks.{capability}.{field}`: the field is the last part, the capability the
 * rest.
 *
 * A tool may name an input `agent`, `context` or `checks` itself. Written bare, those words keep their meaning
 * here, so such an input is written `params.agent.team`: `params.` always names an input, whatever comes after.
 */
export function parseOperand(operand: string): LeftOperand | null {
  if (typeof operand !== "string" || operand.length === 0) return null;
  const dot = operand.indexOf(".");
  const head = dot < 0 ? "" : operand.slice(0, dot);
  if (head === "params") {
    const path = operand.slice(dot + 1);
    return parseInputPath(path) ? { scope: "params", path } : null;
  }
  if (!(RULE_SCOPES as readonly string[]).includes(head)) return parseInputPath(operand) ? { scope: "params", path: operand } : null;
  const rest = operand.slice(dot + 1);
  if (!rest || rest.split(".").some((part) => part.length === 0)) return null;
  if (head !== "checks") return { scope: head as RuleScope, path: rest };
  const last = rest.lastIndexOf(".");
  return last <= 0 ? null : { scope: "checks", capability: rest.slice(0, last), path: rest.slice(last + 1) };
}

/** A reference and the tests that it is there, innermost value last. */
interface Access {
  /** Tests joined by `&&` before the value is read. */
  guards: string[];
  ref: string;
  /** For a path through lists: wraps the comparison in one `.all(…)` per list, outermost first. */
  wrap: (inner: string) => string;
}

function access(operand: LeftOperand): Access {
  if (operand.scope === "checks") {
    const answers = `checks[${JSON.stringify(operand.capability)}]`;
    return {
      guards: [`${JSON.stringify(operand.capability)} in checks`, `${JSON.stringify(operand.path)} in ${answers}`],
      ref: member(answers, operand.path),
      wrap: (inner) => inner,
    };
  }
  const steps = parseInputPath(operand.path)!;
  let base: string = operand.scope;
  let guards: string[] = [];
  const opened: { guards: string[]; list: string; item: string }[] = [];
  for (const step of steps) {
    guards.push(`${JSON.stringify(step.name)} in ${base}`);
    base = member(base, step.name);
    if (step.each) {
      const item = `i${opened.length + 1}`;
      opened.push({ guards, list: base, item });
      guards = [];
      base = item;
    }
  }
  return {
    guards,
    ref: base,
    wrap: (inner) => opened.reduceRight((body, list) => [...list.guards, `${list.list}.all(${list.item}, ${body})`].join(" && "), inner),
  };
}

/** A value as CEL writes it. A number is written as a double: the call's numbers arrive as doubles. */
function literal(value: unknown, kind: InputKind): string {
  if (kind === "decimal") {
    // §13.1 — written as its text, never a number: a number was already a float.
    if (typeof value !== "string" || !DECIMAL_PATTERN.test(value)) throw new TypeError(`VIA: a decimal's value is written as a text of digits: ${JSON.stringify(value)}`);
    return `decimal(${JSON.stringify(value)})`;
  }
  if (typeof value === "string") return kind === "datetime" ? `timestamp(${JSON.stringify(value)})` : JSON.stringify(value);
  if (typeof value === "boolean") return String(value);
  if (typeof value === "number" && Number.isFinite(value)) return Number.isInteger(value) ? `${value}.0` : String(value);
  throw new TypeError(`VIA: a rule's value is none of a text, a number and a boolean: ${JSON.stringify(value)}`);
}

const listOf = (value: unknown, kind: InputKind) => `[${(Array.isArray(value) ? value : [value]).map((v) => literal(v, kind)).join(", ")}]`;

/** The kind a condition's `left` has: declared by the tool for an input, read off the value otherwise. */
function kindFor(condition: LimitCondition, operand: LeftOperand, inputs: JsonSchema | undefined): { kind: InputKind; items?: InputKind } {
  if (operand.scope === "params") return inputAt(inputs, operand.path) ?? { kind: "unknown" };
  const sample = Array.isArray(condition.value) ? condition.value[0] : condition.value;
  return { kind: typeof sample === "number" ? "number" : typeof sample === "boolean" ? "boolean" : "text" };
}

function conditionExpression(condition: LimitCondition, inputs: JsonSchema | undefined): string {
  const operand = parseOperand(condition.left);
  if (!operand) throw new TypeError(`VIA: a rule's \`left\` names nothing: ${JSON.stringify(condition.left)}`);
  const left = access(operand);
  const { kind, items } = kindFor(condition, operand, inputs);
  const of = kind === "list" ? (items ?? "unknown") : kind;
  const typed = (ref: string, as: InputKind) => (as === "datetime" ? `timestamp(${ref})` : as === "decimal" ? `decimal(${ref})` : ref);
  const value = typed(left.ref, kind);
  const guards = [...left.guards];
  let other: string;
  if (condition.right !== undefined) {
    const right = parseOperand(condition.right);
    if (!right) throw new TypeError(`VIA: a rule's \`right\` names nothing: ${JSON.stringify(condition.right)}`);
    const answer = access(right);
    guards.push(...answer.guards);
    other = typed(answer.ref, kind);
  } else {
    other = "";
  }
  const values = () => (condition.right !== undefined ? other : listOf(condition.value, of));
  const one = () => (condition.right !== undefined ? other : literal(condition.value, of));

  let comparison: string;
  const test = TEXT_TESTS[condition.operator];
  if (condition.measure) {
    // A length or a count is a whole number, and `size()` answers an int.
    comparison = `size(${left.ref}) ${condition.operator} ${Math.trunc(Number(condition.value))}`;
  } else {
    switch (condition.operator) {
      case "in":
        comparison = `${value} in ${values()}`;
        break;
      case "not_in":
        comparison = `!(${value} in ${values()})`;
        break;
      case "starts_with":
      case "ends_with":
      case "contains":
        comparison = `${values()}.exists(s, ${left.ref}.${test}(s))`;
        break;
      case "every_starts_with":
      case "every_ends_with":
      case "every_contains":
        comparison = `${left.ref}.all(item, ${values()}.exists(s, item.${test}(s)))`;
        break;
      case "every_in":
        comparison = `${left.ref}.all(item, ${typed("item", of)} in ${values()})`;
        break;
      case "none_in":
        comparison = `!${left.ref}.exists(item, ${typed("item", of)} in ${values()})`;
        break;
      case "includes_all":
        comparison = of === "decimal" ? `${values()}.all(value, ${left.ref}.exists(item, decimal(item) == value))` : `${values()}.all(value, value in ${left.ref})`;
        break;
      default:
        comparison = `${value} ${condition.operator} ${one()}`;
    }
  }
  return left.wrap([...guards, comparison].join(" && "));
}

/**
 * §15.4 — the CEL a rule's conditions generate. One condition is written as it is; several, a policy's exception,
 * are joined by OR, each in parentheses. A signed rule's `expression` is this, byte for byte (`ruleIssues`).
 */
export function ruleExpression(conditions: LimitCondition[], inputs?: JsonSchema): string {
  const parts = conditions.map((c) => conditionExpression(c, inputs));
  return parts.length === 1 ? parts[0]! : parts.map((p) => `(${p})`).join(" || ");
}

/** A rule from its conditions, with the expression they generate. */
export function buildRule(conditions: LimitCondition[], inputs?: JsonSchema, otherwise?: "mandate"): LimitRule {
  return { conditions, expression: ruleExpression(conditions, inputs), ...(otherwise ? { otherwise } : {}) };
}

const isScalar = (v: unknown) => typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));

/** What a value must be for an operator over a kind; a sentence when it is not, else null. */
function valueIssue(condition: LimitCondition, kind: InputKind, items: InputKind | undefined): string | null {
  const { operator, value } = condition;
  const fits = (v: unknown, of: InputKind) =>
    of === "number" || of === "integer" ? typeof v === "number" && Number.isFinite(v) && (of === "number" || Number.isInteger(v))
    : of === "boolean" ? typeof v === "boolean"
    : of === "text" ? typeof v === "string"
    : of === "datetime" ? typeof v === "string" && !Number.isNaN(Date.parse(v))
    : of === "decimal" ? typeof v === "string" && DECIMAL_PATTERN.test(v)
    : isScalar(v);
  if (condition.measure) return Number.isInteger(value) && (value as number) >= 0 ? null : "a length or a count is compared with a whole number";
  const of = kind === "list" ? (items ?? "unknown") : kind;
  const many = operator === "in" || operator === "not_in" || ITEM_OPERATORS.includes(operator);
  const anyOf = operator in TEXT_TESTS;
  if (many) return Array.isArray(value) && value.length > 0 && value.every((v) => fits(v, of)) ? null : `\`${operator}\` takes a list of values of the input's kind`;
  if (anyOf) {
    const texts = Array.isArray(value) ? value : [value];
    return texts.length > 0 && texts.every((v) => typeof v === "string" && v.length > 0) ? null : `\`${operator}\` takes a text, or a list of them`;
  }
  return fits(value, of) ? null : `\`${operator}\` takes one value of the input's kind`;
}

/**
 * §15.4 — what stops a rule being signed, in words; empty when it may be. The issuer's check, for a policy version
 * and for a mandate: a verifier runs a signed rule's expression as written.
 */
export function ruleIssues(rule: LimitRule, place: RulePlace): string[] {
  const issues: string[] = [];
  if (!rule || !Array.isArray(rule.conditions) || rule.conditions.length === 0) return ["a rule has no conditions"];
  if (place.document === "mandate" && rule.conditions.length !== 1) {
    issues.push("a mandate's rule has one condition: every condition must hold, so none is a way around another");
  }
  if (rule.otherwise !== undefined && (rule.otherwise !== "mandate" || place.document === "mandate")) {
    issues.push("`otherwise` is `mandate`, and only on a policy's or an app's rule");
  }
  for (const c of rule.conditions) {
    const at = `condition on ${JSON.stringify(c?.left)}`;
    const operand = c ? parseOperand(c.left) : null;
    if (!operand) {
      issues.push(`${at}: \`left\` names nothing`);
      continue;
    }
    if ((c.value === undefined) === (c.right === undefined)) issues.push(`${at}: carries a \`value\` or a \`right\`, and only one`);
    if (c.right !== undefined) {
      if (place.document === "mandate") issues.push(`${at}: a mandate's condition carries a \`value\`, so a person approves numbers they can read`);
      else if (parseOperand(c.right)?.scope !== "checks") issues.push(`${at}: \`right\` names a check's answer (\`checks.{capability}.{field}\`), never an input of the same call`);
    }
    if (place.root && operand.scope !== "agent" && operand.scope !== "accreditation") {
      issues.push(`${at}: a root rule reads only \`agent.*\` and \`accreditation.*\``);
      continue;
    }
    if (place.document === "mandate" && operand.scope === "checks") issues.push(`${at}: a mandate's rule reads no check`);
    if (operand.scope === "agent" && operand.path === "did" && c.operator === "not_in" && rule.conditions.length > 1) {
      issues.push(`${at}: an exception names the agents that get it — \`in\`, never \`not_in\`, beside other conditions`);
    }
    let kind: InputKind = "unknown";
    let items: InputKind | undefined;
    if (operand.scope === "params") {
      const declared = inputAt(place.inputs, operand.path);
      if (!declared) {
        issues.push(`${at}: the tool declares no such input`);
        continue;
      }
      ({ kind, items } = declared);
    }
    if (c.measure !== undefined) {
      const measured = c.measure === "length" ? kind === "text" : c.measure === "count" ? kind === "list" : false;
      if (!measured) issues.push(`${at}: \`measure\` is \`length\` of a text or \`count\` of a list`);
      else if (!COMPARISONS.includes(c.operator)) issues.push(`${at}: a length or a count takes a number comparison`);
    } else {
      const allowed =
        operand.scope !== "params" ? SCOPED_OPERATORS
        : kind === "list" ? (items === "text" ? OPERATORS_BY_KIND.list : items === "unknown" || items === "object" || items === "list" || items === undefined ? [] : ITEM_OPERATORS)
        : OPERATORS_BY_KIND[kind];
      if (!allowed.includes(c.operator)) issues.push(`${at}: \`${c.operator}\` is not an operator for ${kind === "unknown" ? "an input of no declared kind" : `the kind ${kind}`}`);
    }
    if (c.right === undefined && c.value !== undefined) {
      const wrong = operand.scope === "params" ? valueIssue(c, kind, items) : valueIssue(c, "unknown", undefined);
      if (wrong) issues.push(`${at}: ${wrong}`);
    }
  }
  if (issues.length === 0) {
    let generated: string | undefined;
    try {
      generated = ruleExpression(rule.conditions, place.inputs);
    } catch (e) {
      issues.push((e as Error).message);
    }
    if (generated !== undefined && rule.expression !== generated) issues.push("`expression` is not what the conditions generate");
  }
  return issues;
}

/** What a rule reads when it runs (§15.4). `params` already carries the tool's defaults. */
export interface RuleEnv {
  params: Record<string, unknown>;
  agent: Record<string, unknown>;
  accreditation?: Record<string, unknown>;
  context?: Record<string, unknown>;
  /** §13.2 — each check's answer, by its capability's name. */
  checks?: Record<string, Record<string, unknown>>;
}

/** §15.4, §15.8 — run one rule, and say where it stands. Anything but `true` is not a pass. */
export function evaluateLimitRule(rule: LimitRule, env: RuleEnv, at: Pick<LimitEvaluation, "in" | "tool" | "rule">): LimitEvaluation {
  const ran = evaluateCel(rule.expression, { ...env, accreditation: env.accreditation ?? {}, context: env.context ?? {}, checks: env.checks ?? {} });
  return { ...at, result: ran.result, ...(ran.reason ? { reason: ran.reason } : {}) };
}
