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

export interface PolicyEntry {
  /** A tool's name, as calls present it (§16.6). */
  tool: string;
  effect: PolicyEffect;
  /** With `rules` only, and required there. It lists `tool` in its `tools` (§0.6.1). */
  action?: PolicyActionRef;
  /** The agents the entry applies to, by DID. Absent: every agent. One naming the agent wins (§21.1). */
  agents?: string[];
  /** Who confirms a step-up on this entry, replacing the policy's `approvers` (§21.3). */
  approvers?: string[];
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
  entries: PolicyEntry[];
}

/** A version as a verifier holds it: the content, and the digest its `POLICY_PUBLISHED` names. */
export interface PolicyVersion {
  content: ViaPolicy;
  policyDigest: string;
}
