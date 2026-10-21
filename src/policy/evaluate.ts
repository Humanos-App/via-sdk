import { actionDigestSRI } from "../action/build.js";
import { constantValues, validateExecutionParams } from "../action/execution-params.js";
import type { ActionDetail } from "../action/types.js";
import { evaluateRules, executionParamsRead, type RuleEvaluation } from "../cel/evaluate.js";
import { policyEntriesFor } from "./build.js";
import type { PolicyActionRef, PolicyEntry, PolicyGuardrailRef, ViaPolicy } from "./types.js";

/** One call, as the policy reads it (§21.3). */
export interface PolicyCall {
  /** The tool the call presents — the `action` its PoP signs (§16.6). */
  tool: string;
  params: Record<string, unknown>;
  /** The CEL `agent.*` environment (§9.3); its `did` picks the entries. */
  agent: Record<string, unknown> & { did?: string };
  /**
   * The kind of mandate the call is made under (§16.4) — absent with no mandate. A plain `authorization` is refused
   * under `authorizations: "deny"` (§21.1).
   */
  mandate?: "guardrail" | "authorization";
  /** Under a guardrail mandate: the id of the action version it pins (§16.4), which a `mandate` entry's `under` reads. */
  mandateAction?: string;
}

export interface PolicyEvaluationDeps {
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  /**
   * §21.1 — every tool any published version of a guardrail's action lists: the versions Humanos groups as one
   * action (§0.6). Required when the policy has a guardrail entry — without it a block by guardrail would match
   * nothing, so the evaluator throws rather than read the policy as allowing.
   */
  guardrailTools?: (guardrail: PolicyGuardrailRef) => ReadonlySet<string> | Promise<ReadonlySet<string>>;
  /**
   * §18.5–§18.6 — the operator's accreditation, asked for only when a rule the policy runs reads
   * `accreditation`. A failure denies with its reason; absent, the rule errors and denies (§16.8).
   */
  loadAccreditation?: () =>
    | Record<string, unknown>
    | undefined
    | { denied: true; reason: string }
    | Promise<Record<string, unknown> | undefined | { denied: true; reason: string }>;
  /**
   * §21.1 — the id of every published version of the action a `{ id }` names: the versions Humanos groups as one (§0.6).
   * Required when a call under a mandate meets a `mandate` entry naming `under` — without it no mandate could be told
   * to be under it, so the evaluator throws rather than read the entry as met.
   */
  actionVersions?: (action: PolicyGuardrailRef) => ReadonlySet<string> | Promise<ReadonlySet<string>>;
}

/**
 * What the policy says of one call. `allow`: with no mandate the call may run; under one, the policy
 * does not object. `deny`: refused, whatever a mandate grants. `mandate`: a person's mandate is needed —
 * under a mandate, no objection.
 */
export interface PolicyEvaluation {
  outcome: "allow" | "deny" | "mandate";
  /**
   * On `deny`: `policy_denied`; `mandate_required` under a mandate the deciding entries' `under` does not name; or what
   * made the policy's own action unusable.
   */
  reason?: string;
  evaluations: RuleEvaluation[];
  /** The entry that decided — the most restrictive of the winning level (§21.1). */
  entry?: PolicyEntry;
  /** On `allow`: an entry's action asks for a step-up on the tool, and who may confirm it (§21.3). */
  stepUp?: { approvers: string[] };
  /** On `allow` through a tool's `rules`: the action marks the tool unrestricted, so no rule ran (§0.6.1). */
  unrestricted?: true;
  /**
   * On `mandate`, and on a `mandate_required` deny: the actions the deciding `mandate` entries name in `under` — a
   * mandate under any one of them meets them (§21.1), and the agent can ask for one (§21.3).
   */
  under?: PolicyGuardrailRef[];
}

const passed = (evaluations: RuleEvaluation[]) => evaluations.every((e) => e.result === "pass" || e.result === "skip");
const NO_TOOLS: ReadonlySet<string> = new Set();

/**
 * §21.3 — the organization's policy over one call: a plain authorization under `authorizations: "deny"`, its
 * `everyCall` rules, then the entries of the most specific level for the tool and the agent (§21.1), the most
 * restrictive deciding. A deny at any step denies. The caller combines the outcome with a mandate when one is
 * presented, and runs a step-up the outcome asks for.
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
      constants: constantValues(action),
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

  // 0. Plain authorizations, where the organization refuses them (§21.1).
  if (call.mandate === "authorization" && policy.authorizations === "deny") return deny("policy_denied");

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

  // 2. The entries for the tool and the agent: the most specific level's, most restrictive first (§21.1).
  const guardrails = [...new Set(policy.entries.flatMap((e) => (e.guardrail ? [e.guardrail.id] : [])))];
  if (guardrails.length && !deps.guardrailTools) {
    throw new TypeError("VIA: this policy targets guardrails, and no guardrailTools is wired (v0.3 §21.1)");
  }
  const tools = new Map<string, ReadonlySet<string>>();
  for (const id of guardrails) tools.set(id, await deps.guardrailTools!({ id }));
  const agentDid = typeof call.agent.did === "string" ? call.agent.did : undefined;
  const entries = policyEntriesFor(policy, call.tool, agentDid, (g) => tools.get(g.id) ?? NO_TOOLS);
  const top = entries[0];
  if (!top || top.effect === "mandate") {
    // §21.1 — the `mandate` entries naming an `under` decide, and a mandate under any one of their actions is enough:
    // a mandate pins one action. One naming none adds nothing beside them.
    const under = entries.flatMap((e) => (e.effect === "mandate" && e.under ? [e.under] : []));
    const mark = { evaluations, ...(top ? { entry: top } : {}), ...(under.length ? { under } : {}) };
    if (under.length && call.mandate && !(await isUnder(call, under, deps))) return { outcome: "deny", reason: "mandate_required", ...mark };
    return { outcome: "mandate", ...mark };
  }
  if (top.effect === "deny") return deny("policy_denied", top);
  if (top.effect === "allow") return { outcome: "allow", evaluations, entry: top };

  // `rules`: every `rules` entry of the level must pass (two guardrails can list one tool).
  let stepUp: { approvers: string[] } | undefined;
  let unrestricted = false;
  for (const entry of entries.filter((e) => e.effect === "rules")) {
    if (!entry.action) return deny("policy_denied", entry);
    const action = await load(entry.action);
    if (typeof action === "string") return deny(action, entry);
    if (entry.tool !== undefined) {
      // A tool's entry: its action as §0.8 rows 7–8 run a pinned one, over the rules that govern the tool.
      if (!action.tools?.includes(call.tool)) return deny("policy_denied", entry);
      try {
        validateExecutionParams(action, call.params);
      } catch (e) {
        return deny(`execution_params_invalid:${(e as Error).message}`, entry);
      }
    }
    // A guardrail's entry: its rules over the call, row 7 aside — it governs calls of several shapes — and
    // `requires` refusing a call that leaves out what a rule reads: a cap a payment cannot dodge.
    const ctx = await env(action);
    if ("denied" in ctx) return deny(ctx.denied as string, entry);
    const r = evaluateRules(action.rules, ctx);
    evaluations.push(...r.evaluations);
    if (!passed(r.evaluations)) return deny("policy_denied", entry);
    const governed = action.rules.some((rule) => !rule.appliesTo?.length || rule.appliesTo.includes(call.tool));
    // A listed tool neither governed nor unrestricted is the version §0.8 refuses.
    if (entry.tool !== undefined && !governed && !action.unrestricted?.includes(call.tool)) return deny("policy_denied", entry);
    unrestricted = entry.tool !== undefined && !governed;
    if (!stepUp && action.stepUp?.tools.includes(call.tool)) stepUp = { approvers: entry.approvers ?? policy.approvers ?? [] };
  }
  return {
    outcome: "allow",
    evaluations,
    entry: top,
    ...(stepUp ? { stepUp } : {}),
    ...(unrestricted ? { unrestricted: true as const } : {}),
  };
}

/** §21.1 — is the call's mandate a guardrail pinning a version of one of these actions? A plain authorization never is. */
async function isUnder(call: PolicyCall, under: PolicyGuardrailRef[], deps: PolicyEvaluationDeps): Promise<boolean> {
  if (call.mandate !== "guardrail" || !call.mandateAction) return false;
  if (!deps.actionVersions) {
    throw new TypeError("VIA: this policy names `under`, and no actionVersions is wired (v0.3 §21.1)");
  }
  for (const action of under) if ((await deps.actionVersions(action)).has(call.mandateAction)) return true;
  return false;
}
