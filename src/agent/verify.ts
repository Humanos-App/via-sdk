// Agent-binding verification (§16.7 / §16.11 — agent-direct). Two entry points:
//  • verifyAgentBinding — the PoP identity checks A1–A6 + A8 (pure; returns the
//    validated rung as an `agent.*` env). A7 (the rung floor) is CEL over `agent.*`
//    at step 8, not a separate check (§16.8 / C1).
//  • verifyAgentDirect — the full §16.11 flow: status/validity/audience + A1–A8 +
//    the action CEL (with the rung env) + step-up → `rechallenge` (D7).
import { actionHash, decodePoP, verifyPoPSignature } from "./pop.js";
import { jwkThumbprint } from "../crypto/p256.js";
import { evaluateRules, type RuleEvaluation } from "../cel/evaluate.js";
import { agentReasonForRule } from "./constraints.js";
import { unwrapUserParamValues, validateExecutionParams } from "../action/execution-params.js";
import { actionDigestSRI } from "../action/build.js";
import type { ActionDetail } from "../action/types.js";
import type { AgentReasonCode, Assurance, Binding, BoundKey, Root } from "./types.js";
import type { CredentialStatus, ViaMandateCredential } from "../types.js";

/** The validated rung, surfaced into the CEL context as `agent.*` (§16.8). */
export interface AgentEnv {
  assurance: Assurance;
  binding: Binding;
  root?: Root;
  verifiedAt: number;
}

export interface PopCheckInput {
  /**
   * Whose key is presenting — `agent` (the default) or `user`/`organization`. Selects the permitted
   * PoP algorithms (§16.6): agents ES256-only because §16.2 chose P-256 for keys the ISSUER
   * controls; a person's authenticator chooses for them, so RS256 and EdDSA are permitted there.
   */
  actorType?: string;
  authorizedAgents: BoundKey[];
  pop: string; // the via-pop+jwt JWS
  verifier: string; // aud
  mandateId: string;
  action: string;
  params: Record<string, unknown>;
}
export interface PopCheckDeps {
  /** A5 — single-use/freshness of the PoP nonce; returns 'ok' or a deny reason. */
  validateNonce?: (nonce: string, mandateId: string) => string | Promise<string>;
  now?: Date;
}
export interface PopCheckResult {
  ok: boolean;
  reason?: AgentReasonCode;
  agent?: AgentEnv;
  boundKey?: BoundKey;
}

/** §16.7 A1–A6 + A8 — decode, select the bound key, verify the signature, aud, nonce, action_hash, staleness. */
export async function verifyAgentBinding(input: PopCheckInput, deps: PopCheckDeps = {}): Promise<PopCheckResult> {
  const d = decodePoP(input.pop); // A1: typ/alg/structure
  if (!d.ok || !d.payload || !d.jkt) return { ok: false, reason: d.reason ?? "pop_invalid" };

  const bk = input.authorizedAgents.find((k) => jwkThumbprint(k.cnf.jwk) === d.jkt); // A2
  if (!bk) return { ok: false, reason: "agent_not_bound" };

  if (!(await verifyPoPSignature(input.pop, bk.cnf.jwk))) return { ok: false, reason: "pop_invalid" }; // A3
  if (d.payload.aud !== input.verifier) return { ok: false, reason: "aud_mismatch" }; // A4

  if (deps.validateNonce) {
    const r = await deps.validateNonce(d.payload.nonce, input.mandateId); // A5
    if (r !== "ok") return { ok: false, reason: r as AgentReasonCode };
  }

  if (d.payload.action_hash !== actionHash(input.mandateId, input.action, input.params)) {
    return { ok: false, reason: "action_hash_mismatch" }; // A6
  }

  const now = (deps.now ?? new Date()).getTime(); // A8
  if (bk.maxAttestationStaleness !== undefined && now - bk.verifiedAt > bk.maxAttestationStaleness * 1000) {
    return { ok: false, reason: "attestation_stale" };
  }

  return { ok: true, boundKey: bk, agent: { assurance: bk.assurance, binding: bk.binding, root: bk.root, verifiedAt: bk.verifiedAt } };
}

export interface CredentialRecordLike {
  status: CredentialStatus;
  validFrom?: string;
  validUntil?: string;
  authorizedDIDs?: string[];
}

export interface AgentDirectDeps {
  /** The calling relying party's identity (the PoP `aud`). */
  verifier: { did: string };
  loadCredentialRecord: (urn: string) => CredentialRecordLike | Promise<CredentialRecordLike>;
  loadActionVersion: (actionId: string) => ActionDetail | null | Promise<ActionDetail | null>;
  validateNonce?: (nonce: string, mandateId: string) => string | Promise<string>;
  /** §17.4 — does this action/amount require a fresh grantor step-up? */
  requiresStepUp?: (action: string, params: Record<string, unknown>) => boolean | Promise<boolean>;
  /** Whether a fresh grantor step-up assertion accompanied this request (verified elsewhere, §17.4). */
  stepUpSatisfied?: boolean;
  now?: Date;
  /**
   * v0.3 §9.3 — EXTENDED `agent.*` fields (bootstrapAnchor, status, …) merged
   * into the CEL env beside the shipped assurance/binding. There is no separate
   * `actor.*` namespace: the artifact is actor-generic, projections are
   * role-specific.
   */
  agentEnvExtras?: Record<string, unknown>;
}

export interface AgentDirectResult {
  decision: "allow" | "deny" | "rechallenge";
  credentialId?: string;
  reason?: string;
  evaluations: RuleEvaluation[];
  agent?: AgentEnv;
}

const deny = (reason: string, credentialId?: string): AgentDirectResult => ({ decision: "deny", reason, credentialId, evaluations: [] });

/**
 * Full agent-direct verify (§16.11). The agent carries the mandate + a PoP; the RP
 * checks authority (status/validity/audience), identity+possession (A1–A8), and the
 * rung floor + action rules as CEL over `agent.*`. Returns `allow | deny | rechallenge`.
 */
export async function verifyAgentDirect(
  mandate: ViaMandateCredential,
  req: { pop: string; action: string; params: Record<string, unknown> },
  deps: AgentDirectDeps,
): Promise<AgentDirectResult> {
  const urn = mandate.id;
  const m = mandate.credentialSubject.mandate;
  const now = deps.now ?? new Date();

  // 2–3. status + validity (trusted record)
  const record = await deps.loadCredentialRecord(urn);
  if (record.status !== "ACTIVE") return deny(`credential_${record.status.toLowerCase()}`, urn);
  if (record.validFrom && new Date(record.validFrom) > now) return deny("not_yet_valid", urn);
  if (record.validUntil && new Date(record.validUntil) < now) return deny("expired", urn);

  // 4. audience — the verifier must be authorized to use the mandate
  const authorizedDIDs = record.authorizedDIDs ?? m.context.authorizedDIDs;
  if (!authorizedDIDs.includes(deps.verifier.did)) return deny("verifier_not_authorized", urn);

  // 5. agent binding is REQUIRED when the mandate carries authorizedAgents (§16.4)
  const boundKeys = m.context.authorizedAgents;
  if (!boundKeys || boundKeys.length === 0) return deny("agent_not_bound", urn);
  const pop = await verifyAgentBinding(
    { authorizedAgents: boundKeys, pop: req.pop, verifier: deps.verifier.did, mandateId: urn, action: req.action, params: req.params },
    { validateNonce: deps.validateNonce, now },
  );
  if (!pop.ok || !pop.agent) return deny(pop.reason ?? "pop_invalid", urn);

  // 5b. step-up (§17.4) — valid, but the human must re-authorize this payment first (D7).
  if (deps.requiresStepUp && (await deps.requiresStepUp(req.action, req.params)) && !deps.stepUpSatisfied) {
    return { decision: "rechallenge", credentialId: urn, reason: "stepup_required", evaluations: [], agent: pop.agent };
  }

  // 6. no action → allow (identity already proven)
  if (!m.action) return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent };

  // 6b. load + pin-check the ActionVersion
  const action = await deps.loadActionVersion(m.action.id);
  if (!action) return deny("action_not_found", urn);
  if (m.action.digestSRI && actionDigestSRI(action) !== m.action.digestSRI) return deny("action_invalid", urn);

  // 7. executionParams shape
  try {
    validateExecutionParams(action, req.params);
  } catch (e) {
    return deny(`execution_params_invalid:${(e as Error).message}`, urn);
  }

  // 8. no rules → allow
  if (!action.rules || action.rules.length === 0) return { decision: "allow", credentialId: urn, evaluations: [], agent: pop.agent };

  // 9. CEL — with the rung env as `agent.*` (this is where A7 is enforced).
  // v0.3: the env EXTENDS with actor-projection fields (bootstrapAnchor, status)
  // supplied by the deployment — same namespace, no `actor.*` (v0.3 §9.3).
  const { decision, evaluations } = evaluateRules(action.rules, {
    userParams: unwrapUserParamValues(m.userParams),
    executionParams: req.params,
    agent: { ...pop.agent, ...(deps.agentEnvExtras ?? {}) },
  });
  if (decision === "allow") return { decision: "allow", credentialId: urn, evaluations, agent: pop.agent };

  // map the first failing rule to a specific agent reason (A7) or the generic rule_failed
  const firstFail = evaluations.find((e) => e.result !== "pass");
  const reason = (firstFail && agentReasonForRule(firstFail.rule)) ?? "rule_failed";
  return { decision: "deny", credentialId: urn, reason, evaluations, agent: pop.agent };
}
