import { Environment, evaluate as celEvaluate, parse as celParse } from "@marcbachmann/cel-js";
import type { ActionRule } from "../action/types.js";
import { rewriteCelTimestamps } from "./timestamps.js";

export interface CelContext {
  /** Issuer constants, unwrapped to `{ name: value }`. */
  userParams: Record<string, unknown>;
  /** Verifier-supplied runtime values. */
  executionParams: Record<string, unknown>;
  /** §16.8 — the acting agent's verified rung `{ assurance, binding, root, verifiedAt, did }`. Present only under agent binding. */
  agent?: Record<string, unknown>;
  /**
   * §18 — the operator's accreditation `{ level, method, registrar, verifiedAt }` (v0.3 §18.5/§18.6),
   * resolved from the operator's own actor. Present only when a rule asked for it and it resolved.
   *
   * Named for the AXIS, not the role. `agent.operator.org` is a different thing — the actor's
   * relationship pointer, saying who an agent acts for. One word meaning both is what this
   * rename removed.
   */
  accreditation?: Record<string, unknown>;
}

export interface RuleEvaluation {
  rule: string;
  /**
   * `skip` (S13): the rule declares `appliesTo` and this call's tool is not in it, so the rule did
   * not run. Recorded rather than omitted — "did not apply" and "passed" are different facts, and
   * an audit that cannot tell them apart cannot answer what actually constrained a call.
   */
  result: "pass" | "fail" | "error" | "skip";
  reason?: string;
}

export interface EvaluationResult {
  decision: "allow" | "deny";
  evaluations: RuleEvaluation[];
}

/**
 * ISO datetimes use native instant semantics; finite JSON numbers keep their exact value.
 * Return dyn for every overload: cel-js otherwise infers the first overload's timestamp type
 * even for a numeric runtime argument and applies timestamp operators to a number.
 * Equality needs an explicit refusal too: default cross-type != would allow a mixed pair.
 */
const CEL_ENVIRONMENT = new Environment({ unlistedVariablesAreDyn: true })
  .registerFunction("viaTimestamp(string): dyn", nativeTimestamp)
  .registerFunction("viaTimestamp(int): dyn", nativeTimestamp)
  .registerFunction("viaTimestamp(double): dyn", (value: number) => {
    if (!Number.isFinite(value)) throw new Error("numeric datetime must be finite");
    return value;
  })
  .registerOperator("double == google.protobuf.Timestamp", () => {
    throw new Error("datetime comparison must not mix string and numeric representations");
  });

function nativeTimestamp(value: unknown): unknown {
  return celEvaluate("timestamp(value)", { value });
}

/**
 * §16.8 — `assuranceRank(x)` maps the ordinal assurance ladder to an int
 * (`pop`=1, `device`=2, `hardware`=3) so CEL floors can compare. cel-js has no
 * user functions, so — as with `timestamp()` — we resolve each call against the
 * context and substitute the literal int before evaluating. The arg is either a
 * quoted literal (`assuranceRank("hardware")`) or a ref (`assuranceRank(agent.assurance)`).
 */
const ASSURANCE_RANK_RE = /assuranceRank\(([^()]*)\)/g;
const ASSURANCE_RANK: Record<string, number> = { pop: 1, device: 2, hardware: 3 };

/** §18 — the accreditation ladder, same ordinal trick as `assuranceRank`. */
const OPERATOR_RANK_RE = /accreditationRank\(([^()]*)\)/g;
const ACCREDITATION_RANK: Record<string, number> = { unverified: 1, domain: 2, verified: 3 };

function resolveAssuranceArg(ref: string, ctx: CelContext): unknown {
  const t = ref.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) return t.slice(1, -1);
  return resolveRef(t, ctx);
}

/** Resolve a dotted ref (`executionParams.when`) against the context; undefined if not a plain path. */
function resolveRef(ref: string, ctx: CelContext): unknown {
  let cur: unknown = ctx;
  for (const part of ref.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/**
 * An argument that is not on the ladder is an AUTHORING ERROR, and it must not rank.
 *
 * Substituting `0` — what this did before 2026-09-12 — turns a rule that reads like a floor into one
 * that passes for everything: `assuranceRank(agent.runtime) >= assuranceRank("tee")` becomes
 * `0 >= 0`, i.e. TRUE for an actor with no runtime evidence at all, and a typo'd token
 * (`assuranceRank("hardwaer")`) does the same. §9.2 and §9.4ter say why the mistake is easy to make:
 * `binding`, `bootstrapAnchor` and `runtime` are CATEGORICAL and "MUST be matched categorically —
 * never passed to a rank helper".
 *
 * So throwing is the whole fix: `evaluateRule` catches it as `result: "error"`, `evaluateRules`
 * denies on anything that is not `pass`, and the verifier reports the rule. That is the same
 * fail-closed reading the fold already takes on an unknown rung (`invalid_assurance`).
 */
const rank = (table: Record<string, number>, fn: string, inner: string, ctx: CelContext): string => {
  const v = resolveAssuranceArg(inner, ctx);
  if (typeof v !== "string" || !(v in table)) {
    throw new Error(
      `${fn}(${inner.trim()}) is not on the ladder (${Object.keys(table).join(" < ")})${
        v === undefined ? ": the value is absent" : `: got ${JSON.stringify(v)}`
      }. A categorical axis is matched with \`in\`, never ranked (v0.3 §9.2).`,
    );
  }
  return String(table[v]);
};

function prepare(expression: string, ctx: CelContext): string {
  let withRanks = expression.replace(ASSURANCE_RANK_RE, (_whole, inner: string) => rank(ASSURANCE_RANK, "assuranceRank", inner, ctx));
  withRanks = withRanks.replace(OPERATOR_RANK_RE, (_whole, inner: string) => rank(ACCREDITATION_RANK, "accreditationRank", inner, ctx));
  return rewriteCelTimestamps(withRanks);
}

/**
 * Does this expression PARSE? Syntax only — nothing is evaluated and no context is needed.
 *
 * For the boundary where a rule is written rather than run: a malformed expression is otherwise
 * stored intact and only shows up at verification, where it reads as `error` → deny. That is the
 * safe direction, but it strands a mandate nobody can use and blames the call instead of the rule.
 * Rejecting at the door hands the message to whoever can still fix it — which, since an agent may
 * PROPOSE rules, is often not a person.
 *
 * Parsing is not meaning: a rule that parses can still reference a param that does not exist, or
 * return a non-boolean. Both are caught at evaluation (`result: "error"`), and neither can be
 * decided here without the action's params and a runtime context.
 */
export const CEL_EXPRESSION_MAX_LENGTH = 2000;

export function validateCelExpression(expression: string): { ok: true } | { ok: false; error: string } {
  if (typeof expression !== "string" || expression.trim() === "") {
    return { ok: false, error: "expression is empty" };
  }
  // Size is the attack surface here, not semantics. PARSING never runs the expression — that is
  // `evaluate`, and nothing calls it at this door — so a hostile rule cannot compute. What it can
  // still do is make the PARSER work: a megabyte of operators, or nesting deep enough to exhaust
  // the stack. The length cap bounds both before the parser sees the string.
  if (expression.length > CEL_EXPRESSION_MAX_LENGTH) {
    return { ok: false, error: `expression is longer than ${CEL_EXPRESSION_MAX_LENGTH} characters` };
  }
  try {
    celParse(expression);
    return { ok: true };
  } catch (e) {
    // Catches RangeError (stack exhaustion from deep nesting) as well as ParseError: both are
    // "this is not a rule we accept", and neither should reach a caller as a 500.
    const first = (e as Error)?.message?.split("\n")[0]?.trim() ?? "";
    // The reason quotes the input back. Bound it: it travels into logs and into an agent's context.
    const reason = first.length > 200 ? `${first.slice(0, 200)}…` : first;
    return { ok: false, error: reason || "expression could not be parsed" };
  }
}

/**
 * The `executionParams` fields an expression reads, from its parse tree — `executionParams.amount` and
 * `executionParams["max-results"]`, never the same words inside a string. Null when it does not parse.
 * v0.3 §21.1: an `everyCall` rule is `skip` on a call that carries none of one of them.
 */
export function executionParamsRead(expression: string): string[] | null {
  let ast: unknown;
  try {
    ast = celParse(expression).ast;
  } catch {
    return null;
  }
  const read = new Set<string>();
  const isScope = (n: unknown) => (n as { op?: unknown; args?: unknown })?.op === "id" && (n as { args?: unknown }).args === "executionParams";
  const visit = (node: unknown): void => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    const { op, args } = node as { op?: unknown; args?: unknown };
    if (typeof op !== "string") return;
    if ((op === "." || op === ".?") && Array.isArray(args) && isScope(args[0]) && typeof args[1] === "string") read.add(args[1]);
    if (op === "[]" && Array.isArray(args) && isScope(args[0])) {
      const key = args[1] as { op?: unknown; args?: unknown };
      if (key?.op === "value" && typeof key.args === "string") read.add(key.args);
    }
    visit(args);
  };
  visit(ast);
  return [...read];
}

export function evaluateRule(rule: Pick<ActionRule, "name" | "description" | "expression">, ctx: CelContext): RuleEvaluation {
  try {
    const value = CEL_ENVIRONMENT.evaluate(prepare(rule.expression, ctx), ctx as unknown as Record<string, unknown>);
    if (typeof value !== "boolean") {
      return { rule: rule.name, result: "error", reason: `rule did not return a boolean (got ${typeof value})` };
    }
    return value
      ? { rule: rule.name, result: "pass" }
      : { rule: rule.name, result: "fail", reason: rule.description ?? "constraint not satisfied" };
  } catch (e) {
    return { rule: rule.name, result: "error", reason: (e as Error).message };
  }
}

/**
 * Does this rule govern this call (S13)? `appliesTo` names the tools it governs; absent, it governs
 * everything.
 */
function governs(rule: Pick<ActionRule, "appliesTo">, ctx: CelContext): boolean {
  if (!rule.appliesTo || rule.appliesTo.length === 0) return true;
  const tool = ctx.executionParams?.tool;
  return typeof tool === "string" && rule.appliesTo.includes(tool);
}

/**
 * Evaluate all rules; `allow` only if every rule that GOVERNS this call passes.
 *
 * Two S13 behaviours sit here:
 *
 *   - a rule the call is outside of (`appliesTo`) is recorded `skip` and does not decide;
 *   - a rule that governs the call and names `requires` DENIES when the call omits one of those
 *     parameters, rather than letting the limit be skipped. The old shape expressed the same
 *     intent as `!has(executionParams.p) || …`, which is the permissive direction: omit the
 *     parameter and the person's allowlist never runs.
 */
export function evaluateRules(
  rules: Pick<ActionRule, "name" | "description" | "expression" | "appliesTo" | "requires">[],
  ctx: CelContext,
): EvaluationResult {
  const evaluations = rules.map((r): RuleEvaluation => {
    if (!governs(r, ctx)) return { rule: r.name, result: "skip", reason: "tool not governed by this rule" };
    const missing = (r.requires ?? []).find((param) => ctx.executionParams?.[param] === undefined);
    if (missing !== undefined) {
      return { rule: r.name, result: "fail", reason: `required_param_missing:${missing}` };
    }
    return evaluateRule(r, ctx);
  });
  const decision = evaluations.every((e) => e.result === "pass" || e.result === "skip") ? "allow" : "deny";
  return { decision, evaluations };
}
