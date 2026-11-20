/**
 * v0.4 §15.4–§15.8 — one tool call, decided by the policy's limits and, where the policy leaves it to a person, a
 * mandate's. Pure: the caller has already proved who calls (the PoP), resolved the tool's definition, and checked
 * the mandate's own authority (its stamp, status, dates, bound key). The reviewer (§15.2) is the caller's too.
 */
import { NO_LAYER_CONTEXT, unfilledTokens, type CallLayerContext } from "../datalayer/policy.js";
import { capabilityDigest, capabilityInputSchema, type ViaCapability } from "../apps/capability.js";
import { leavesToAPerson, policyToolFor } from "./policy.js";
import { ONLY_FOR_SKIPPED, evaluateLimitRule, ruleAppliesTo, type RuleEnv } from "./rule.js";
import { inputsWithDefaults, nameOnlyHash, toolDefinitionHash, undeclaredInput } from "./tool.js";
import type { LimitEvaluation, LimitRule, LimitsPolicy, MandateLimits, ToolDefinition } from "./types.js";

/** One call, as its limits read it. */
export interface LimitsCall {
  /** The tool's key, as the policy and a mandate name it: `server/name`, or a capability's name. */
  tool: string;
  params: Record<string, unknown>;
  /**
   * A server's tool: its definition as it stands now — what its `hash` is checked against, and what declares its
   * inputs. Not read for a capability.
   */
  definition?: ToolDefinition;
  /**
   * §13.1, §15.3 — a capability: the version a member approved, and the digest of every version published. The
   * call runs on the current version, so it may be made from any of them; the inputs it may carry are the approved
   * version's, and a parameter added after it is `param_undeclared`.
   */
  capability?: { approved: ViaCapability; published: readonly string[] };
  /** `agent.*` (v0.3 §9.3); its `did` is what an exception names. */
  agent: Record<string, unknown>;
  /**
   * §15.3 — the hash of the definition the caller made the call from, as it reports it. Required: a record of the
   * tool is only as fresh as its last declaration, so a call from another definition, or one that names none, is
   * refused `tool_changed` at once. Where the agent makes the call itself this is its word, as its inputs are.
   */
  madeFrom: string;
  /**
   * §15.7.2 — the agent is one that proves no definition (a host that only speaks MCP, its key Humanos's to hold):
   * `madeFrom` is not read, the call is decided against the definition on record, and a tool that requires proof is
   * refused. Set by the verifier from how the agent was registered, never from the call.
   */
  unproven?: true;
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
  /** §14.8 — the call's context, as Humanos established it. Absent, a call with no layer: a rule always has one to read. */
  context?: CallLayerContext;
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
 * input the tool does not declare (`param_undeclared`); a token left in the arguments (`token_unfilled`, §14.5); the tool's rules (`policy_denied`, or, for a rule that
 * leaves its failure to a person, on to the mandate); a tool under the default, which nobody may grant
 * (`mandate_required`, naming no grantor); a tool that requires proof, for an agent that proves no definition
 * (`tool_proof_required`); then the mandate — none (`mandate_required`), one that does
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
  // §13.0 — a tool the policy knows by name only has no definition to read: its hash is its name's, its inputs unchecked.
  const nameOnly = entry?.nameOnly === true;
  if (!nameOnly && !call.capability && !call.definition) throw new TypeError("VIA: a call is decided against its tool's definition, or its capability's approved version (v0.4 §15.3)");
  const inputs = nameOnly ? undefined : call.capability ? capabilityInputSchema(call.capability.approved) : call.definition!.inputSchema;
  const env: RuleEnv = {
    params: inputsWithDefaults(inputs, call.params),
    agent: call.agent,
    ...(accreditation ? { accreditation } : {}),
    context: { ...(deps.context ?? NO_LAYER_CONTEXT) },
    ...(deps.checks ? { checks: deps.checks } : {}),
  };
  // §15.4 — a policy's rule that names its agents (`onlyFor`) runs for a call by one of them, by the DID the call
  // resolved to, which is `agent.did` in a rule. For any other it is `skip`: it neither passes nor fails the call,
  // and leaves nothing to a person. A mandate's rule names no agents: one that does is not run as if it applied.
  const run = (rules: LimitRule[] | undefined, at: Pick<LimitEvaluation, "in" | "tool">, from: "policy" | "mandate" = "policy") =>
    (rules ?? []).map((rule, i) => {
      const where = { ...at, rule: i };
      const result: LimitEvaluation =
        rule.onlyFor === undefined ? evaluateLimitRule(rule, env, where)
        : from === "mandate" ? { ...where, result: "error", reason: "a mandate's rule names no agents (`onlyFor`)" }
        : ruleAppliesTo(rule, call.agent.did) ? evaluateLimitRule(rule, env, where)
        : { ...where, result: "skip", reason: ONLY_FOR_SKIPPED };
      evaluations.push(result);
      return { rule, passed: result.result === "pass" || result.result === "skip" };
    });

  // 1. The policy's root rules: the agent and its accreditation, whatever the tool.
  if (run(policy.rules, { in: policyRef }).some((r) => !r.passed)) return deny("policy_denied");

  // 2. The tool's entry, its server's, or the default. A tool under `default: mandate` has no entry, so nobody to
  // grant it (§15.5): no mandate counts until a member names the tool in the policy, with its definition and its
  // grantors. The answer names none, which says so.
  if (entry ? entry.effect === "deny" : policy.default === "deny") return deny("policy_denied");
  if (!entry) return deny("mandate_required", "policy", { tool: call.tool, grantors: [] });

  // 3. The definition the call was made from, the one the policy pins, and the inputs the tool declares.
  const hash = nameOnly ? nameOnlyHash(call.tool)! : call.capability ? capabilityDigest(call.capability.approved) : toolDefinitionHash(call.definition!);
  if (call.unproven) {
    // §15.7.2 — nothing names the definition: a tool that asks for proof is refused until Humanos makes the call.
    if (entry.proof === "required") return deny("tool_proof_required", "policy", { tool: call.tool });
  } else {
    if (typeof call.madeFrom !== "string" || !call.madeFrom) return deny("tool_changed", "policy", { detail: "the call names no definition of the tool" });
    const known = !nameOnly && call.capability ? call.capability.published.includes(call.madeFrom) : call.madeFrom === hash;
    if (!known) return deny("tool_changed", "policy", { detail: "the call was made from another definition than the one on record" });
  }
  // §15.7.2 — a tool being upgraded has two approved definitions: the call is decided against the one it holds.
  const approved = [entry.hash, entry.earlier?.hash].filter((h): h is string => typeof h === "string");
  if (entry.hash !== undefined && !approved.includes(hash)) return deny("tool_changed");
  const undeclared = nameOnly ? null : undeclaredInput(inputs, call.params);
  if (undeclared) return deny("param_undeclared", "policy", { input: undeclared });
  // §14.5 — a token left in the arguments was refused, never issued, or marks a removed value: the tool never runs
  // with one. The reason is written for the model that made the call.
  const token = unfilledTokens(call.tool, call.params, policy.context)[0];
  if (token) return deny("token_unfilled", "policy", { input: token.at, detail: token.reason });

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
  const own = [...run(mandate.limits.rules, { in: mandate.id }, "mandate"), ...run(mandateTool.rules, { in: mandate.id, tool: call.tool }, "mandate")];
  if (own.some((r) => !r.passed)) return deny("rule_failed", "mandate", asks);
  return { outcome: "allow", evaluations, on: "mandate", ...unset, ...asks };
}
