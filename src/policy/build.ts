import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import type { ActionDetail } from "../action/types.js";
import { POLICY_EFFECTS, type PolicyActionRef, type PolicyEntry, type ViaPolicy } from "./types.js";

/** §21.2 — the digest a `POLICY_PUBLISHED` names: the §0.5.3 `digestSRI` of the version's JCS form. */
export function policyDigest(policy: ViaPolicy): string {
  return computeSRI(canonicalizeRFC8785(policy));
}

/**
 * §21.1 — the entry for a call of `tool` by `agentDid`: the most specific that applies. One naming the
 * agent beats one naming no agents, and publishing refuses two at the same level, so the order of the
 * entries never decides. None is the default: a person's mandate is needed.
 */
export function policyEntryFor(policy: Pick<ViaPolicy, "entries">, tool: string, agentDid: string | undefined): PolicyEntry | undefined {
  const forTool = policy.entries.filter((e) => e.tool === tool);
  const named = agentDid ? forTool.find((e) => e.agents?.length && e.agents.includes(agentDid)) : undefined;
  return named ?? forTool.find((e) => !e.agents?.length);
}

/** What the publish check needs to know beyond the policy: the platform's records, read beforehand. */
export interface PolicyPublishContext {
  /** A published ActionVersion of the organization's own, by reference; null when it is none of those. */
  ownAction: (ref: PolicyActionRef) => ActionDetail | null;
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

  if (policy.everyCall) {
    const action = ctx.ownAction(policy.everyCall);
    if (!action) issues.push("`everyCall` is not a published action of the organization's own");
    else if (action.tools) issues.push("the `everyCall` action lists `tools`: it governs every call, whatever the tool");
    else if (action.rules.some((r) => r.appliesTo?.length)) issues.push("an `everyCall` rule names a tool: it governs every call");
  }
  for (const did of policy.approvers ?? []) if (!ctx.isMember(did)) issues.push(`approver ${did} is not a member of the organization`);

  const seen = new Set<string>();
  for (const [i, e] of policy.entries.entries()) {
    const at = `entry ${i + 1} (${e.tool})`;
    if (typeof e.tool !== "string" || e.tool.length === 0) issues.push(`entry ${i + 1} names no tool`);
    if (!POLICY_EFFECTS.includes(e.effect)) issues.push(`${at} has an effect outside allow, deny, rules and mandate`);
    if (e.effect === "rules" && !e.action) issues.push(`${at} is \`rules\` with no action`);
    if (e.effect !== "rules" && e.action) issues.push(`${at} names an action without being \`rules\``);
    if (e.action) {
      const action = ctx.ownAction(e.action);
      if (!action) issues.push(`${at}: its action is not a published action of the organization's own`);
      else if (!action.tools?.includes(e.tool)) issues.push(`${at}: its action does not list ${e.tool} in \`tools\``);
    }
    for (const did of e.agents ?? []) if (!ctx.operates(did)) issues.push(`${at}: the organization does not operate ${did}`);
    for (const did of e.approvers ?? []) if (!ctx.isMember(did)) issues.push(`${at}: approver ${did} is not a member of the organization`);
    // One entry per tool at each level: for every agent, and for each agent named.
    for (const level of e.agents?.length ? e.agents : ["*"]) {
      const key = `${e.tool}\u0000${level}`;
      if (seen.has(key)) issues.push(`${at} overlaps another entry for ${e.tool}${level === "*" ? "" : ` and ${level}`}`);
      seen.add(key);
    }
  }
  return issues;
}
