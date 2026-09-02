import { evaluate as celEvaluate } from "@marcbachmann/cel-js";
import type { ActionRule } from "../action/types.js";

export interface CelContext {
  /** Issuer constants, unwrapped to `{ name: value }`. */
  userParams: Record<string, unknown>;
  /** Verifier-supplied runtime values. */
  executionParams: Record<string, unknown>;
  /** §16.8 — the acting agent's verified rung `{ assurance, binding, root, verifiedAt, did }`. Present only under agent binding. */
  agent?: Record<string, unknown>;
  /** §18 — the composed operator identity `{ level, method, subjectType, registrar, org }`. Present only under operator verification. */
  operator?: Record<string, unknown>;
}

export interface RuleEvaluation {
  rule: string;
  result: "pass" | "fail" | "error";
  reason?: string;
}

export interface EvaluationResult {
  decision: "allow" | "deny";
  evaluations: RuleEvaluation[];
}

/**
 * N31: the rule generator emits `timestamp(ref)` around `datetime` refs.
 *
 * `@marcbachmann/cel-js` implements `timestamp()` natively over RFC-3339 strings
 * and int epochs, comparing by **instant** — so `…00Z` equals `…00.000Z`, and
 * `10:00+01:00` equals `09:00Z`, which a lexicographic string compare gets wrong.
 * That is the correct behaviour and what we want for the spec's ISO-8601 datetime
 * contract. But the engine **throws** on a JS number (`timestamp(double)`).
 *
 * So we resolve each wrapped ref against the runtime context and decide per call:
 *  - **string** value → keep native `timestamp()` (correct instant comparison);
 *  - **number** value → strip the wrapper, compare raw epochs (legacy behaviour,
 *    avoids the `timestamp(double)` throw);
 *  - **literal / missing path** → keep native and let the engine resolve it
 *    (e.g. `timestamp("2026-01-01T00:00:00Z")`).
 */
const TIMESTAMP_RE = /timestamp\(([^()]*)\)/g;

/**
 * §16.8 — `assuranceRank(x)` maps the ordinal assurance ladder to an int
 * (`pop`=1, `device`=2, `hardware`=3) so CEL floors can compare. cel-js has no
 * user functions, so — as with `timestamp()` — we resolve each call against the
 * context and substitute the literal int before evaluating. The arg is either a
 * quoted literal (`assuranceRank("hardware")`) or a ref (`assuranceRank(agent.assurance)`).
 */
const ASSURANCE_RANK_RE = /assuranceRank\(([^()]*)\)/g;
const ASSURANCE_RANK: Record<string, number> = { pop: 1, device: 2, hardware: 3 };

/** §18 — the operator identity ladder, same ordinal trick as `assuranceRank`. */
const OPERATOR_RANK_RE = /operatorRank\(([^()]*)\)/g;
const OPERATOR_RANK: Record<string, number> = { unverified: 1, domain: 2, verified: 3 };

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

function prepare(expression: string, ctx: CelContext): string {
  let withRanks = expression.replace(ASSURANCE_RANK_RE, (_whole, inner: string) => {
    const v = resolveAssuranceArg(inner, ctx);
    return String(typeof v === "string" && v in ASSURANCE_RANK ? ASSURANCE_RANK[v] : 0);
  });
  withRanks = withRanks.replace(OPERATOR_RANK_RE, (_whole, inner: string) => {
    const v = resolveAssuranceArg(inner, ctx);
    return String(typeof v === "string" && v in OPERATOR_RANK ? OPERATOR_RANK[v] : 0);
  });
  return withRanks.replace(TIMESTAMP_RE, (whole, inner: string) => {
    const ref = inner.trim();
    return typeof resolveRef(ref, ctx) === "number" ? ref : whole;
  });
}

export function evaluateRule(rule: Pick<ActionRule, "name" | "description" | "expression">, ctx: CelContext): RuleEvaluation {
  try {
    const value = celEvaluate(prepare(rule.expression, ctx), ctx as unknown as Record<string, unknown>);
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

/** Evaluate all rules; `allow` only if every rule passes. */
export function evaluateRules(
  rules: Pick<ActionRule, "name" | "description" | "expression">[],
  ctx: CelContext,
): EvaluationResult {
  const evaluations = rules.map((r) => evaluateRule(r, ctx));
  const decision = evaluations.every((e) => e.result === "pass") ? "allow" : "deny";
  return { decision, evaluations };
}
