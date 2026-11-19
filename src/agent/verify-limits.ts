/**
 * v0.4 §15 — one agent tool call under a policy of v0.4's shape: the proof once, the policy's limits, and a person's
 * mandate only where the policy leaves the call to one. `verifyAgentCall` decides every other policy.
 */
import { jwkThumbprint } from "../crypto/p256.js";
import { MAX_EXECUTIONS_REACHED, unsupportedCriticalExtension, verifyStamp } from "../mandate/build.js";
import { isSupportedSpecVersion } from "../version.js";
import { decideLimits, type LimitsDecision } from "../limits/decide.js";
import { isLimitsMandate, limitsOf } from "../limits/mandate.js";
import { settleReview } from "../limits/review.js";
import type { LimitEvaluation, LimitsPolicy, ReviewerPart, ToolDefinition } from "../limits/types.js";
import { NO_LAYER_CONTEXT, type CallLayerContext } from "../datalayer/policy.js";
import type { AccreditationRevocationReason } from "../operator/types.js";
import {
  _celAgent,
  agentEnvOf,
  attestationStale,
  projectAccreditation,
  verifyAgentBinding,
  withSignedWindow,
  type AccreditationLoad,
  type AgentDirectDeps,
  type AgentEnv,
  type HeldMandate,
} from "./verify.js";
import type { BoundKey } from "./types.js";
import { capabilityDigest, isCapabilityName, type ViaCapability } from "../apps/capability.js";
import { policyToolFor } from "../limits/policy.js";

/** One agent tool call under a v0.4 policy (§15). */
export interface LimitsCallRequest {
  /** The agent the caller resolved: its DID names the policy lane (v0.3 §21.5). */
  agentDid: string;
  pop: string;
  /** The tool's key, as the policy names it: `server/name`, or a capability's name. The PoP signs it as `action`. */
  tool: string;
  params: Record<string, unknown>;
  /** A mandate the agent presents; its PoP then binds the mandate. Read only where the policy leaves the call to one. */
  mandateId?: string;
  /** With no mandate presented: the policy the PoP binds, as the challenge named it (v0.3 §21.4). */
  policy?: string;
  /**
   * §15.3 — the hash of the definition the call was made from, as the caller reports it. Required, and under the
   * PoP (`limitsActionHash`): a call that names none is refused `tool_changed`.
   */
  toolHash: string;
}

export interface LimitsCallDeps extends Pick<AgentDirectDeps, "resolvePublicKey" | "review" | "agentEnvExtras" | "loadAccreditation" | "now"> {
  /** The calling verifier's identity (the PoP `aud`). */
  verifier: { did: string };
  /** The agent's usable keys, resolved through its current actor (v0.3 §21.4). */
  candidates: BoundKey[];
  /** The current version of the agent's operator's policy, of v0.4's shape. */
  policy: { content: LimitsPolicy; policyDigest: string };
  /** v0.3 §16.7 A5 — the nonce the challenge issued for the authority the PoP names. */
  validateNonce: (nonce: string, authority: string) => string | Promise<string>;
  /** The tool's definition on record for this agent; null when there is none, and a pinned tool is then `tool_changed`. */
  toolDefinition: (tool: string) => ToolDefinition | null | Promise<ToolDefinition | null>;
  /**
   * §13.1 — every published version of a capability, by its name. Required when a call presents one: the policy
   * names the version a member approved, and the call may be made from any published one.
   */
  capabilityVersions?: (name: string) => ViaCapability[] | Promise<ViaCapability[]>;
  /** The mandate presented, by its id; null when the verifier holds none of that id. Called only where one is read. */
  loadMandate?: (mandateId: string) => HeldMandate | null | Promise<HeldMandate | null>;
  /**
   * §15.2 — does the reviewer enforce? `false` is v0.3 §20.6's shadow phase: its answer is recorded and refuses
   * nothing, except on a tool the policy marks `reviewer: "required"`. Default `true`.
   */
  reviewEnforces?: boolean;
  /** §14.8 — the call's context, as Humanos established it: never what the agent reports of itself. Absent, none. */
  context?: CallLayerContext;
  /** §13.2 — each check's answer, by its capability's name. */
  checks?: Record<string, Record<string, unknown>>;
}

/**
 * What {@link verifyLimitsCall} answers. It carries no `enforcement`: a §15.2 mandate has one kind (§15.8). Every
 * result names its chain: `credentialId` for a decision taken on a mandate, else the policy lane.
 */
export interface LimitsCallResult {
  decision: "allow" | "deny";
  /** On `deny`: §15.8's code, or one of v0.3's. */
  reason?: string;
  evaluations: LimitEvaluation[];
  credentialId?: string;
  agent?: AgentEnv;
  policy?: string;
  agentDid?: string;
  policyDigest: string;
  /** The `action_hash` the call's PoP bound, once checked. */
  actionHash?: string;
  /** No entry named the tool: the policy's `default` decided it. */
  unset?: true;
  /** With `mandate_required`, `grantor_not_allowed`, `one_call_required`: the tool and who may grant it (§15.8). */
  tool?: string;
  grantors?: string[] | "any";
  /** With `param_undeclared`: the input, as a path. */
  input?: string;
  /** In words, where the code alone would mislead; with `token_unfilled`, the reason the model reads (§14.5). */
  detail?: string;
  /** §14.8 — the call's context its rules read, as Humanos established it. On every result that reached the policy. */
  context?: CallLayerContext;
  /** §15.8 — on a decision under a mandate: what the reviewer did. */
  reviewed?: ReviewerPart;
  /** v0.3 §20.6 — the reviewer that took part, for the audit record. */
  reviewer?: { id: string; version?: string };
  /** v0.3 §18.5 — with `accreditation_revoked`: why. */
  revocationReason?: AccreditationRevocationReason;
}

/**
 * §15.4–§15.8 — one agent tool call, decided policy first. The agent's PoP is checked once, against its own usable
 * keys, over the authority it names. Then the policy: its root rules, the tool's entry, the tool's definition and
 * inputs, the tool's rules. A mandate is loaded only when the policy leaves the call to a person and one was
 * presented; it must be of §15.2's shape, hold its own authority, bind the key that proved, list the tool, come
 * from a grantor the policy allows, and pass its own rules.
 *
 * The reviewer (§15.2) reads a call that passed under a mandate. Its finding refuses where it enforces. With no
 * reviewer, or one out of service or not enforcing, the call is decided without it and the result says so — unless
 * the policy marks the tool `reviewer: "required"`. A reviewer that cannot read this request refuses it: only an
 * outage passes.
 */
export async function verifyLimitsCall(req: LimitsCallRequest, deps: LimitsCallDeps): Promise<LimitsCallResult> {
  if (typeof deps.validateNonce !== "function") {
    throw new TypeError("VIA: verifying a PoP requires deps.validateNonce (v0.3 §16.7 A5) — no nonce check is wired");
  }
  if (!req.mandateId === !req.policy) {
    throw new TypeError("VIA: a call names the mandate its PoP binds or, with none, the policy — exactly one (v0.3 §21.4)");
  }
  const now = deps.now ?? new Date();
  const policy = deps.policy.content;
  const policyDigest = deps.policy.policyDigest;
  const onLane = (decision: LimitsCallResult["decision"], extra: Partial<LimitsCallResult> = {}): LimitsCallResult => ({
    decision,
    evaluations: [],
    policy: policy.$id,
    agentDid: req.agentDid,
    policyDigest,
    ...extra,
  });
  if (!deps.candidates?.length) return onLane("deny", { reason: "agent_not_bound" });
  // §15.3 — the proof covers the definition the call was made from, so one that names none cannot be checked at all.
  if (typeof req.toolHash !== "string" || !req.toolHash) return onLane("deny", { reason: "tool_changed", detail: "the call names no definition of the tool" });

  // v0.3 §16.7 A1–A6 + A8 — once, against the agent's own keys, over the authority the PoP names. The tool's own
  // inputs are the params: a tool may name one `action` or `tool`, so v0.3's discriminator check does not run.
  const authority = req.mandateId ? { mandateId: req.mandateId } : { policy: req.policy };
  const pop = await verifyAgentBinding(
    { authorizedAgents: deps.candidates, pop: req.pop, verifier: deps.verifier.did, ...authority, action: req.tool, params: req.params, toolHash: req.toolHash },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent || !pop.boundKey) return onLane("deny", { reason: pop.reason ?? "pop_invalid" });
  const proof = pop.actionHash ? { actionHash: pop.actionHash } : {};
  if (!req.mandateId && req.policy !== policy.$id) return onLane("deny", { reason: "policy_denied", agent: pop.agent, ...proof });

  // With no definition on record, a stand-in that carries nothing: a tool the policy pins is then `tool_changed`.
  // A capability is read at the version the policy's entry approved; with none approved or published, the same.
  const versions = isCapabilityName(req.tool) ? ((await deps.capabilityVersions?.(req.tool)) ?? []) : [];
  const approved = versions.find((v) => v.version === policyToolFor(policy, req.tool)?.entry.version);
  const subject = approved
    ? { capability: { approved, published: versions.map(capabilityDigest) } }
    : { definition: (isCapabilityName(req.tool) ? null : await deps.toolDefinition(req.tool)) ?? { name: req.tool } };
  let revocationReason: AccreditationRevocationReason | undefined;
  const loadAccreditation = deps.loadAccreditation
    ? async () => {
        const loaded = (await deps.loadAccreditation!()) as AccreditationLoad;
        if (loaded && "denied" in loaded) {
          const failure = loaded as Extract<AccreditationLoad, { denied: true }>;
          revocationReason = failure.revocationReason;
          return { denied: true as const, reason: failure.reason };
        }
        return loaded ? projectAccreditation(loaded as Record<string, unknown>) : undefined;
      }
    : undefined;
  const decide = (agent: AgentEnv, mandate?: Parameters<typeof decideLimits>[2]) =>
    decideLimits(
      policy,
      { tool: req.tool, params: req.params, ...subject, agent: { ..._celAgent(deps.agentEnvExtras, agent), did: req.agentDid }, madeFrom: req.toolHash },
      mandate,
      { ...(loadAccreditation ? { loadAccreditation } : {}), ...(deps.context ? { context: deps.context } : {}), ...(deps.checks ? { checks: deps.checks } : {}) },
    );
  const told = (d: LimitsDecision): Partial<LimitsCallResult> => ({
    ...(d.reason ? { reason: d.reason } : {}),
    evaluations: d.evaluations,
    ...(d.unset ? { unset: true as const } : {}),
    ...(d.tool ? { tool: d.tool } : {}),
    ...(d.grantors !== undefined ? { grantors: d.grantors } : {}),
    ...(d.input ? { input: d.input } : {}),
    ...(d.detail ? { detail: d.detail } : {}),
    context: deps.context ?? NO_LAYER_CONTEXT,
    ...(revocationReason ? { revocationReason } : {}),
  });

  // The policy decides first, with no mandate: one presented for a call the policy settles itself is never loaded.
  const first = await decide(pop.agent);
  if (first.outcome === "allow") return onLane("allow", { ...told(first), agent: pop.agent, ...proof });
  const leftToAPerson = first.reason === "mandate_required" && !(Array.isArray(first.grantors) && first.grantors.length === 0);
  if (!leftToAPerson || !req.mandateId) return onLane("deny", { ...told(first), agent: pop.agent, ...proof });

  if (!deps.loadMandate) throw new TypeError("VIA: the policy left a call to a mandate, and no loadMandate is wired (v0.4 §15)");
  const held = await deps.loadMandate(req.mandateId);
  if (!held) return onLane("deny", { ...told(first), reason: "mandate_not_found", agent: pop.agent, ...proof });
  const mandate = held.mandate;
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const onMandate = (decision: LimitsCallResult["decision"], extra: Partial<LimitsCallResult> = {}): LimitsCallResult => ({
    decision,
    evaluations: first.evaluations,
    credentialId: urn,
    policyDigest,
    ...proof,
    ...extra,
  });
  const refuse = (reason: string, extra: Partial<LimitsCallResult> = {}) => onMandate("deny", { reason, ...extra });
  if (held.denied) return refuse(held.denied);

  // The mandate's own authority (v0.3 §16.11 steps 1–4): its stamp first — a copy edited after issue verifies nothing.
  if (!(await verifyStamp(mandate, deps.resolvePublicKey)).valid) return refuse("credential_stamp_invalid");
  // §15.7 — under a v0.4 policy only a mandate of §15.2's shape opens a tool. v0.3's has no list of tools, and its
  // plain authorization would open them all: it does not count, and the agent is told what to ask for.
  if (!isLimitsMandate(mandate)) {
    if (isSupportedSpecVersion(mandate.specVersion)) return refuse("mandate_required", { tool: req.tool, ...(first.grantors !== undefined ? { grantors: first.grantors } : {}) });
    return refuse("unsupported_spec_version");
  }
  const limits = limitsOf(mandate);
  if (!limits || typeof m.grantor !== "string") return refuse("unsupported_spec_version");
  if (unsupportedCriticalExtension(m, new Set())) return refuse("extension_unsupported");
  const record = held.record;
  if (record.status !== "ACTIVE") return refuse(record.exhausted ? MAX_EXECUTIONS_REACHED : `credential_${record.status.toLowerCase()}`);
  if (record.validFrom && new Date(record.validFrom) > now) return refuse("not_yet_valid");
  if (record.validUntil && new Date(record.validUntil) < now) return refuse("expired");
  if (!(record.authorizedDIDs ?? m.context.authorizedDIDs).includes(deps.verifier.did)) return refuse("verifier_not_authorized");

  // v0.3 §16.7 A2, A8 — the key that proved is one the mandate binds, inside the mandate's own re-attest window.
  const signed = m.context.authorizedAgents ?? [];
  if (signed.length === 0) return refuse("agent_not_bound");
  if (!held.candidates) return refuse("actor_unresolvable");
  const proved = jwkThumbprint(pop.boundKey.cnf.jwk);
  const bound = withSignedWindow(held.candidates, signed).find((k) => jwkThumbprint(k.cnf.jwk) === proved);
  if (!bound) return refuse("agent_not_bound");
  if (attestationStale(bound, now)) return refuse("attestation_stale");
  const agent = agentEnvOf(bound);

  const decided = await decide(agent, { id: urn, grantor: m.grantor, limits });
  if (decided.outcome === "deny") {
    const answer = { ...told(decided), agent, ...proof };
    return decided.on === "mandate" ? onMandate("deny", answer) : onLane("deny", answer);
  }

  // §15.2 — the reviewer reads the call against the words. Where it gives no answer, the call is decided without it.
  const answer = deps.review ? await deps.review({ description: limits.description, action: req.tool, params: req.params, mandateId: urn }) : undefined;
  const settled = settleReview(answer, { enforces: deps.reviewEnforces !== false, required: decided.reviewerRequired === true });
  const part = { ...told(decided), agent, ...(settled.reviewed ? { reviewed: settled.reviewed } : {}), ...(settled.reviewer ? { reviewer: settled.reviewer } : {}) };
  return settled.ok ? onMandate("allow", part) : refuse(settled.reason, part);
}
