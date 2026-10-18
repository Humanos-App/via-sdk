import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import type { ActionDetail } from "../action/types.js";
import {
  POLICY_EFFECTS,
  type PolicyActionRef,
  type PolicyEffect,
  type PolicyEntry,
  type PolicyGuardrailRef,
  type ViaPolicy,
} from "./types.js";

/** §21.2 — the digest a `POLICY_PUBLISHED` names: the §0.5.3 `digestSRI` of the version's JCS form. */
export function policyDigest(policy: ViaPolicy): string {
  return computeSRI(canonicalizeRFC8785(policy));
}

/** The tools a guardrail targets: every tool any published version of its action lists (§21.1). */
export type GuardrailTools = (guardrail: PolicyGuardrailRef) => ReadonlySet<string>;

/** §21.1 — the most restrictive effect first: `deny`, `rules`, `mandate`, `allow`. */
const RESTRICTION: Record<PolicyEffect, number> = { deny: 0, rules: 1, mandate: 2, allow: 3 };

/**
 * §21.1 — the entries for a call of `tool` by `agentDid`: those of the most specific level that has any — a tool
 * entry naming the agent, a guardrail entry naming the agent, a tool entry naming none, a guardrail entry naming none
 * — ordered most restrictive first. Several can apply at one level only through guardrails that list the same tool;
 * the first decides, and every `rules` among them must pass. Empty is the default: a person's mandate is needed.
 */
export function policyEntriesFor(
  policy: Pick<ViaPolicy, "entries">,
  tool: string,
  agentDid: string | undefined,
  toolsOf: GuardrailTools,
): PolicyEntry[] {
  const targets = (e: PolicyEntry) => (e.tool !== undefined ? e.tool === tool : !!e.guardrail && toolsOf(e.guardrail).has(tool));
  const named = (e: PolicyEntry) => !!agentDid && !!e.agents?.length && e.agents.includes(agentDid);
  const general = (e: PolicyEntry) => !e.agents?.length;
  const levels: ((e: PolicyEntry) => boolean)[] = [
    (e) => e.tool !== undefined && named(e),
    (e) => e.guardrail !== undefined && named(e),
    (e) => e.tool !== undefined && general(e),
    (e) => e.guardrail !== undefined && general(e),
  ];
  const applying = policy.entries.filter(targets);
  for (const level of levels) {
    const found = applying.filter(level);
    if (found.length) return found.sort((a, b) => RESTRICTION[a.effect] - RESTRICTION[b.effect]);
  }
  return [];
}

/** What the publish check needs to know beyond the policy: the platform's records, read beforehand. */
export interface PolicyPublishContext {
  /** A published ActionVersion of the organization's own, by reference; null when it is none of those. */
  ownAction: (ref: PolicyActionRef) => ActionDetail | null;
  /** Is this a published action version of the organization's own — a guardrail an entry may target? */
  ownGuardrail: (ref: PolicyGuardrailRef) => boolean;
  /** Does the organization operate this agent? */
  operates: (did: string) => boolean;
  /** Is this person one of the organization's members? Humanos's record: a person's affiliation is v0.4's. */
  isMember: (did: string) => boolean;
}

/**
 * §21.1 — what stops a policy version being published, in words; empty when it may be. The issuer's
 * check before `POLICY_PUBLISHED` is written; a verifier reads a published version as written.
 */
export function policyPublishIssues(policy: ViaPolicy, ctx: PolicyPublishContext): string[] {
  const issues: string[] = [];
  if (policy.type !== "VIAPolicy") issues.push("`type` is not VIAPolicy");
  if (typeof policy.$id !== "string" || !policy.$id.startsWith("urn:via:policy:")) issues.push("`$id` is not a urn:via:policy URN");
  if (!Number.isInteger(policy.version) || policy.version < 1) issues.push("`version` is not a whole number of at least 1");
  if (policy.authorizations !== undefined && policy.authorizations !== "allow" && policy.authorizations !== "deny") {
    issues.push("`authorizations` is neither allow nor deny");
  }

  if (policy.everyCall) {
    const action = ctx.ownAction(policy.everyCall);
    if (!action) issues.push("`everyCall` is not a published action of the organization's own");
    else if (action.tools) issues.push("the `everyCall` action lists `tools`: it governs every call, whatever the tool");
    else if (action.rules.some((r) => r.appliesTo?.length)) issues.push("an `everyCall` rule names a tool: it governs every call");
  }
  for (const did of policy.approvers ?? []) if (!ctx.isMember(did)) issues.push(`approver ${did} is not a member of the organization`);

  const seen = new Set<string>();
  for (const [i, e] of policy.entries.entries()) {
    const target = e.tool !== undefined ? `tool ${e.tool}` : e.guardrail ? `guardrail ${e.guardrail.id}` : undefined;
    const at = `entry ${i + 1}${target ? ` (${target})` : ""}`;
    if ((e.tool !== undefined) === !!e.guardrail) issues.push(`${at} must target a tool or a guardrail, and only one`);
    if (e.tool !== undefined && (typeof e.tool !== "string" || e.tool.length === 0)) issues.push(`${at} names no tool`);
    if (e.guardrail && !ctx.ownGuardrail(e.guardrail)) issues.push(`${at}: its guardrail is not a published action of the organization's own`);
    if (!POLICY_EFFECTS.includes(e.effect)) issues.push(`${at} has an effect outside allow, deny, rules and mandate`);
    if (e.effect === "rules" && !e.action) issues.push(`${at} is \`rules\` with no action`);
    if (e.effect !== "rules" && e.action) issues.push(`${at} names an action without being \`rules\``);
    if (e.action) {
      const action = ctx.ownAction(e.action);
      if (!action) issues.push(`${at}: its action is not a published action of the organization's own`);
      else if (e.tool !== undefined && !action.tools?.includes(e.tool)) issues.push(`${at}: its action does not list ${e.tool} in \`tools\``);
      else if (e.guardrail && action.tools) issues.push(`${at}: its action lists \`tools\`, and a guardrail entry's governs the guardrail's`);
    }
    for (const did of e.agents ?? []) if (!ctx.operates(did)) issues.push(`${at}: the organization does not operate ${did}`);
    for (const did of e.approvers ?? []) if (!ctx.isMember(did)) issues.push(`${at}: approver ${did} is not a member of the organization`);
    // One entry per target at each level: for every agent, and for each agent named.
    if (target) {
      for (const level of e.agents?.length ? e.agents : ["*"]) {
        const key = `${target}\u0000${level}`;
        if (seen.has(key)) issues.push(`${at} overlaps another entry for ${target}${level === "*" ? "" : ` and ${level}`}`);
        seen.add(key);
      }
    }
  }
  return issues;
}
