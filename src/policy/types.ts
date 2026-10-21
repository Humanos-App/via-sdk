/**
 * v0.3 §21 — the organization's policy (`VIAPolicy`): what its agents may do, one per organization, over
 * every call of every agent it operates. Under a mandate it caps the call; with no mandate it is the
 * call's only authority, and a tool it says nothing about still needs a person's mandate.
 */

/** §21.1 — what an entry lets a tool do. `mandate` is what a tool with no entry gets anyway, written out. */
export type PolicyEffect = "allow" | "deny" | "rules" | "mandate";

export const POLICY_EFFECTS: readonly PolicyEffect[] = ["allow", "deny", "rules", "mandate"];

/** A published ActionVersion of the organization's own, pinned as a mandate pins one (§20.5). */
export interface PolicyActionRef {
  id: string;
  digestSRI: string;
}

/**
 * §21.1 — a published action of the organization's own, by any of its versions (the versions Humanos groups as one,
 * §0.6): a guardrail an entry targets, or the action a `mandate` entry's mandate must be under.
 */
export interface PolicyGuardrailRef {
  id: string;
}

export interface PolicyEntry {
  /** A tool's name, as calls present it (§16.6). An entry targets a `tool` or a `guardrail`, never both. */
  tool?: string;
  /** Every tool any published version of this action lists (§21.1) — "Slack is off" in one entry. */
  guardrail?: PolicyGuardrailRef;
  effect: PolicyEffect;
  /**
   * With `rules` only, and required there. On a `tool` entry it lists the tool in its `tools` (§0.6.1); on a
   * `guardrail` entry it lists none — its rules run on each of the guardrail's calls, `requires` refusing one that
   * leaves out what a rule reads.
   */
  action?: PolicyActionRef;
  /** The agents the entry applies to, by DID. Absent: every agent. One naming the agent wins (§21.1). */
  agents?: string[];
  /** Who confirms a step-up on this entry, replacing the policy's `approvers` (§21.3). */
  approvers?: string[];
  /**
   * With `mandate` only (§21.1): the action the call's mandate must be under — a guardrail mandate pinning one of its
   * published versions; a plain authorization never is. Absent, any mandate.
   */
  under?: PolicyGuardrailRef;
}

export interface ViaPolicy {
  /** `urn:via:policy:{uuid}` — shared by all the policy's versions: an organization has one. */
  $id: string;
  type: "VIAPolicy";
  /** 1 for the first, one more for each version published after it. */
  version: number;
  /** Rules every call by every agent must pass, whatever the tool. Its action lists no `tools`. */
  everyCall?: PolicyActionRef;
  /** The organization's members, by DID, who may confirm a step-up under the policy (§21.3). */
  approvers?: string[];
  /** §21.1 — whether its agents may act under a plain authorization, a mandate that pins no action. Default `allow`. */
  authorizations?: "allow" | "deny";
  entries: PolicyEntry[];
}

/** A version as a verifier holds it: the content, and the digest its `POLICY_PUBLISHED` names. */
export interface PolicyVersion {
  content: ViaPolicy;
  policyDigest: string;
}
