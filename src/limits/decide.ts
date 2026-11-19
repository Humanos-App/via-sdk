/**
 * v0.4 §15.4–§15.8 — one tool call, decided by the policy's limits and, where the policy leaves it to a person, a
 * mandate's. Pure: the caller has already proved who calls (the PoP), resolved the tool's definition, and checked
 * the mandate's own authority (its stamp, status, dates, bound key). The reviewer (§15.2) is the caller's too.
 */
import { leavesToAPerson, policyToolFor } from "./policy.js";
import { evaluateLimitRule, type RuleEnv } from "./rule.js";
import { inputsWithDefaults, toolDefinitionHash, undeclaredInput } from "./tool.js";
import type { LimitEvaluation, LimitRule, LimitsPolicy, MandateLimits, ToolDefinition } from "./types.js";

/** One call, as its limits read it. */
export interface LimitsCall {
  /** The tool's key, as the policy and a mandate name it: `server/name`, or a capability's name. */
  tool: string;
  params: Record<string, unknown>;
  /** The tool's definition as it stands now: what its `hash` is checked against, and what declares its inputs. */
  definition: ToolDefinition;
  /** `agent.*` (v0.3 §9.3); its `did` is what an exception names. */
  agent: Record<string, unknown>;
  /**
   * §15.3 — the hash of the definition the caller made the call from, as it reports it. Required: a record of the
   * tool is only as fresh as its last declaration, so a call from another definition, or one that names none, is
   * refused `tool_changed` at once. Where the agent makes the call itself this is its word, as its inputs are.
   */
  madeFrom: string;
}

/** A mandate presented with the call, already held to its own authority by the caller. */
export interface PresentedLimits {
  /** The mandate's URN: what its evaluations name. */
  id: string;
  grantor: string;
  limits: MandateLimits;
}

export interface LimitsDeps {
  /** §18.5–§18.6 — the operator's accreditation, asked for only when a rule reads it. A failure denies with its reason. */
  loadAccreditation?: () =>
    | Record<string, unknown>
    | undefined
    | { denied: true; reason: string }
    | Promise<Record<string, unknown> | undefined | { denied: true; reason: string }>;
  /** §14.8 — the call's context, where the context layer set one. */
  context?: Record<string, unknown>;
  /** §13.2 — each check's answer, by its capability's name. */
  checks?: Record<string, Record<string, unknown>>;
}

export interface LimitsDecision {
  outcome: "allow" | "deny";
  /** On `deny`: §15.8's code. */
  reason?: string;
  evaluations: LimitEvaluation[];
  /** Whose decision it is: the policy's alone, or the mandate's, read because the policy left the call to a person. */
  on: "policy" | "mandate";
  /** No entry named the tool: the policy's `default` decided how it is read. */
  unset?: true;
  /** With `mandate_required`: the tool, and who may grant a mandate for it (§15.5, §15.8). */
  tool?: string;
  grantors?: string[] | "any";
  /** With `param_undeclared`: the input, as a path. */
  input?: string;
  /** In words, where the code alone would mislead: a `tool_changed` for a call that named no definition. */
  detail?: string;
  /** On an allow under a mandate, and on a refusal that needs it: the policy asks for the reviewer on this tool (§15.2). */
  reviewerRequired?: true;
}

const reads = (rules: LimitRule[] | undefined, word: string) => !!rules?.some((r) => r.expression.includes(word));

/**
 * §15.4 — every rule runs: the policy's root rules, its rules for the tool, then the mandate's root rules and its
 * rules for the tool. Any failure denies, and the deny names where its rule stands.
 *
 * The order of refusals: the root rules; a tool the policy denies; a definition that changed, on record or in the
 * caller's hands (`tool_changed`); an
 * input the tool does not declare (`param_undeclared`); the tool's rules (`policy_denied`, or, for a rule that
 * leaves its failure to a person, on to the mandate); a tool under the default, which nobody may grant
 * (`mandate_required`, naming no grantor); then the mandate — none (`mandate_required`), one that does
 * not list the tool (`tool_not_covered`), another definition (`tool_changed`), a grantor the policy does not allow
 * (`grantor_not_allowed`), more than one call where one is required (`one_call_required`), its rules
 * (`rule_failed`).
 */
export async function decideLimits(policy: LimitsPolicy, call: LimitsCall, mandate: PresentedLimits | undefined, deps: LimitsDeps = {}): Promise<LimitsDecision> {
  const evaluations: LimitEvaluation[] = [];
  const policyRef = `${policy.$id}#${policy.version}`;
  const found = policyToolFor(policy, call.tool);
  const entry = found?.entry;
  const unset = found ? {} : ({ unset: true } as const);
  const deny = (reason: string, on: LimitsDecision["on"] = "policy", extra: Partial<LimitsDecision> = {}): LimitsDecision => ({ outcome: "deny", reason, evaluations, on, ...unset, ...extra });

  const mandateTool = mandate?.limits.tools?.[call.tool];
  const every = [...(policy.rules ?? []), ...(entry?.rules ?? []), ...(mandate?.limits.rules ?? []), ...(mandateTool?.rules ?? [])];
  let accreditation: Record<string, unknown> | undefined;
  if (reads(every, "accreditation")) {
    const loaded = deps.loadAccreditation ? await deps.loadAccreditation() : undefined;
    if (loaded && "denied" in loaded) return deny(String(loaded.reason));
    // An operator with no accreditation is the unverified tier (v0.3 §18.6); with no loader at all, the rule errors.
    accreditation = loaded ?? (deps.loadAccreditation ? { level: "unverified" } : undefined);
  }
  const env: RuleEnv = {
    params: inputsWithDefaults(call.definition.inputSchema, call.params),
    agent: call.agent,
    ...(accreditation ? { accreditation } : {}),
    ...(deps.context ? { context: deps.context } : {}),
    ...(deps.checks ? { checks: deps.checks } : {}),
  };
  const run = (rules: LimitRule[] | undefined, at: Pick<LimitEvaluation, "in" | "tool">) =>
    (rules ?? []).map((rule, i) => {
      const result = evaluateLimitRule(rule, env, { ...at, rule: i });
      evaluations.push(result);
      return { rule, passed: result.result === "pass" };
    });

  // 1. The policy's root rules: the agent and its accreditation, whatever the tool.
  if (run(policy.rules, { in: policyRef }).some((r) => !r.passed)) return deny("policy_denied");

  // 2. The tool's entry, its server's, or the default. A tool under `default: mandate` has no entry, so nobody to
  // grant it (§15.5): no mandate counts until a member names the tool in the policy, with its definition and its
  // grantors. The answer names none, which says so.
  if (entry ? entry.effect === "deny" : policy.default === "deny") return deny("policy_denied");
  if (!entry) return deny("mandate_required", "policy", { tool: call.tool, grantors: [] });

  // 3. The definition the call was made from, the one the policy pins, and the inputs the tool declares.
  const hash = toolDefinitionHash(call.definition);
  if (typeof call.madeFrom !== "string" || !call.madeFrom) return deny("tool_changed", "policy", { detail: "the call names no definition of the tool" });
  if (call.madeFrom !== hash) return deny("tool_changed", "policy", { detail: "the call was made from another definition than the one on record" });
  if (entry.hash !== undefined && entry.hash !== hash) return deny("tool_changed");
  const undeclared = undeclaredInput(call.definition.inputSchema, call.params);
  if (undeclared) return deny("param_undeclared", "policy", { input: undeclared });

  // 4. The policy's rules for the tool. One that leaves its failure to a person sends the call to a mandate.
  const ran = run(entry.rules, { in: policyRef, tool: call.tool });
  if (ran.some((r) => !r.passed && r.rule.otherwise !== "mandate")) return deny("policy_denied");
  const settledByAPerson = ran.some((r) => !r.passed);
  if (entry.effect === "allow" && !settledByAPerson) return { outcome: "allow", evaluations, on: "policy" };

  // 5. A person's mandate. Under a v0.4 policy only one of §15.2's shape that lists the tool counts (§15.7).
  const grantors = leavesToAPerson(entry) ? entry.grantors : undefined;
  const asks = entry.reviewer === "required" ? ({ reviewerRequired: true } as const) : {};
  const named = { tool: call.tool, ...(grantors !== undefined ? { grantors } : {}) };
  if (!mandate) return deny("mandate_required", "policy", named);
  if (!mandateTool) return deny("tool_not_covered", "mandate");
  if (mandateTool.hash !== hash) return deny("tool_changed", "mandate");
  if (grantors !== "any" && !grantors?.includes(mandate.grantor)) return deny("grantor_not_allowed", "mandate", named);
  if ((entry.oneCall === true || settledByAPerson) && mandate.limits.maxExecutions !== 1) return deny("one_call_required", "mandate", named);

  // 6. The mandate's rules, frozen when it was signed.
  const own = [...run(mandate.limits.rules, { in: mandate.id }), ...run(mandateTool.rules, { in: mandate.id, tool: call.tool })];
  if (own.some((r) => !r.passed)) return deny("rule_failed", "mandate", asks);
  return { outcome: "allow", evaluations, on: "mandate", ...unset, ...asks };
}
