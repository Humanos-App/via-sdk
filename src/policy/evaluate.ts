import { actionDigestSRI } from "../action/build.js";
import { validateExecutionParams } from "../action/execution-params.js";
import type { ActionDetail } from "../action/types.js";
import { evaluateRules, executionParamsRead, type RuleEvaluation } from "../cel/evaluate.js";
import { policyEntryFor } from "./build.js";
import type { PolicyActionRef, PolicyEntry, ViaPolicy } from "./types.js";

/** One call, as the policy reads it (§21.3). */
export interface PolicyCall {
  /** The tool the call presents — the `action` its PoP signs (§16.6). */
  tool: string;
  params: Record<string, unknown>;
  /** The CEL `agent.*` environment (§9.3); its `did` picks the entry. */
  agent: Record<string, unknown> & { did?: string };
}

export interface PolicyEvaluationDeps {
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  /**
   * §18.5–§18.6 — the operator's accreditation, asked for only when a rule the policy runs reads
   * `accreditation`. A failure denies with its reason; absent, the rule errors and denies (§16.8).
   */
  loadAccreditation?: () =>
    | Record<string, unknown>
    | undefined
    | { denied: true; reason: string }
    | Promise<Record<string, unknown> | undefined | { denied: true; reason: string }>;
}

/**
 * What the policy says of one call. `allow`: with no mandate the call may run; under one, the policy
 * does not object. `deny`: refused, whatever a mandate grants. `mandate`: a person's mandate is needed —
 * under a mandate, no objection.
 */
export interface PolicyEvaluation {
  outcome: "allow" | "deny" | "mandate";
  /** On `deny`: `policy_denied`, or what made the policy's own action unusable. */
  reason?: string;
  evaluations: RuleEvaluation[];
  entry?: PolicyEntry;
  /** On `allow`: the entry's action asks for a step-up on the tool, and who may confirm it (§21.3). */
  stepUp?: { approvers: string[] };
  /** On `allow` through `rules`: the action marks the tool unrestricted, so no rule ran (§0.6.1). */
  unrestricted?: true;
}

const passed = (evaluations: RuleEvaluation[]) => evaluations.every((e) => e.result === "pass" || e.result === "skip");

/**
 * §21.3 — the organization's policy over one call: its `everyCall` rules, then the most specific entry
 * for the tool and the agent. A deny at any step denies. The caller combines the outcome with a
 * mandate when one is presented, and runs a step-up the outcome asks for.
 */
export async function evaluatePolicy(policy: ViaPolicy, call: PolicyCall, deps: PolicyEvaluationDeps): Promise<PolicyEvaluation> {
  const evaluations: RuleEvaluation[] = [];
  const deny = (reason: string, entry?: PolicyEntry): PolicyEvaluation => ({ outcome: "deny", reason, evaluations, ...(entry ? { entry } : {}) });
  let accreditation: Record<string, unknown> | undefined;
  let accreditationAsked = false;

  // A rule names the tool it governs by `executionParams.tool`, which is the tool presented (§16.6).
  const env = async (action: ActionDetail) => {
    if (!accreditationAsked && action.rules.some((r) => String(r.expression ?? "").includes("accreditation"))) {
      accreditationAsked = true;
      const loaded = deps.loadAccreditation ? await deps.loadAccreditation() : undefined;
      if (loaded && "denied" in loaded) return { denied: loaded.reason };
      accreditation = loaded ?? (deps.loadAccreditation ? { level: "unverified" } : undefined);
    }
    return {
      userParams: {},
      executionParams: { ...call.params, tool: call.tool },
      agent: call.agent,
      ...(accreditation ? { accreditation } : {}),
    };
  };
  const load = async (ref: PolicyActionRef): Promise<ActionDetail | string> => {
    const action = await deps.loadActionVersion(ref.id);
    if (!action) return "action_not_found";
    return actionDigestSRI(action) === ref.digestSRI ? action : "action_invalid";
  };

  // 1. Rules for every call. The params' shape is not checked: they govern calls of every shape. A rule
  // reading a parameter the call does not carry is `skip` (§21.1) — `amount <= 5000` holds for the calls
  // that state an amount and leaves a search alone. One that does not parse runs, and errors: a deny.
  if (policy.everyCall) {
    const action = await load(policy.everyCall);
    if (typeof action === "string") return deny(action);
    const ctx = await env(action);
    if ("denied" in ctx) return deny(ctx.denied as string);
    const carried: Record<string, unknown> = { ...call.params, tool: call.tool };
    for (const rule of action.rules) {
      const lacking = (executionParamsRead(rule.expression) ?? []).find((p) => carried[p] === undefined);
      evaluations.push(
        lacking !== undefined
          ? { rule: rule.name, result: "skip", reason: `the call carries no ${lacking}` }
          : evaluateRules([rule], ctx).evaluations[0]!,
      );
    }
    if (!passed(evaluations)) return deny("policy_denied");
  }

  // 2. The entry for the tool and the agent.
  const entry = policyEntryFor(policy, call.tool, typeof call.agent.did === "string" ? call.agent.did : undefined);
  if (!entry || entry.effect === "mandate") return { outcome: "mandate", evaluations, ...(entry ? { entry } : {}) };
  if (entry.effect === "deny") return deny("policy_denied", entry);
  if (entry.effect === "allow") return { outcome: "allow", evaluations, entry };

  // `rules`: the action decides, as a pinned one does at §0.8 rows 7–8 — over the rules that govern the tool.
  if (!entry.action) return deny("policy_denied", entry);
  const action = await load(entry.action);
  if (typeof action === "string") return deny(action, entry);
  if (!action.tools?.includes(call.tool)) return deny("policy_denied", entry);
  try {
    validateExecutionParams(action, call.params);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, entry);
  }
  const ctx = await env(action);
  if ("denied" in ctx) return deny(ctx.denied as string, entry);
  const r = evaluateRules(action.rules, ctx);
  evaluations.push(...r.evaluations);
  if (!passed(r.evaluations)) return deny("policy_denied", entry);
  const governed = action.rules.some((rule) => !rule.appliesTo?.length || rule.appliesTo.includes(call.tool));
  // A listed tool neither governed nor unrestricted is the version §0.8 refuses.
  if (!governed && !action.unrestricted?.includes(call.tool)) return deny("policy_denied", entry);
  const asks = action.stepUp?.tools.includes(call.tool) ?? false;
  return {
    outcome: "allow",
    evaluations,
    entry,
    ...(asks ? { stepUp: { approvers: entry.approvers ?? policy.approvers ?? [] } } : {}),
    ...(!governed ? { unrestricted: true as const } : {}),
  };
}
