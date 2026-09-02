// The §18 operator gate (O1–O5) and the ∧ composition that produces `operator.*` for
// CEL. Mirrors §16.7's A1–A8: ordered, first failure denies, no I/O (all injected).
//
// TWO RULES THAT CARRY THE DESIGN:
//
//  1. **Absence ≠ impersonation.** No credential presented ⇒ the agent simply floors at
//     `unverified` and PASSES (`ok: true`). That is the normal, high-volume tier — the
//     ❔ badge, not ⚠️. A failure is only ever a credential that was PRESENTED and did
//     not hold up (forged, revoked, expired, or an affiliation the org never signed).
//
//  2. **Inheritance = credential ∧ affiliation.** A registrar-signed "Acme is verified"
//     grants an agent nothing on its own; Acme must ALSO have signed "this agent
//     operates for us". Without that link the agent floors at `unverified` no matter how
//     verified Acme is — otherwise any agent could name Acme and inherit its green check.
import { verifyOperatorCredential } from "./credential.js";
import { verifyAffiliation } from "./affiliation.js";
import type { ViaEvent, BitstringStatusListEntry } from "../types.js";
import type {
  OperatorEnv,
  OperatorReasonCode,
  OperatorRevocationReason,
  ViaOperatorCredential,
} from "./types.js";

export interface OperatorVerifyInput {
  /** The agent whose effective operator level we are computing. */
  agentDid: string;
  /** The registrar-signed operator credential, if the agent presents one. */
  credential?: ViaOperatorCredential | null;
  /** The org-signed `operates` link, if the agent presents one. */
  affiliation?: ViaEvent | null;
}

export interface OperatorVerifyDeps {
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>;
  /**
   * **O3** — resolve the PUBLISHED status list entry (offline; no live registrar call,
   * preserving the agent-direct property §16.11). Omit to skip revocation checking.
   */
  checkStatus?: (entry: BitstringStatusListEntry) => Promise<{ revoked: boolean; reason?: OperatorRevocationReason }> | { revoked: boolean; reason?: OperatorRevocationReason };
  now?: Date;
}

export interface OperatorVerifyResult {
  ok: boolean;
  /** Always present — floors at `unverified` rather than being absent. */
  operator: OperatorEnv;
  reason?: OperatorReasonCode;
  /** Human-readable detail behind `reason`. */
  detail?: string;
  /** Present on `operator_revoked` — underwriters need the *why*. */
  revocationReason?: OperatorRevocationReason;
}

const UNVERIFIED: OperatorEnv = { level: "unverified" };

/**
 * Run O1–O4 and compose the effective operator environment. O5 (the CEL floor) is
 * evaluated by the rule engine against the returned `operator` — exactly as A7 is
 * CEL over `agent.*`.
 */
export async function verifyOperator(input: OperatorVerifyInput, deps: OperatorVerifyDeps): Promise<OperatorVerifyResult> {
  const now = deps.now ?? new Date();

  // Nothing presented → the normal unverified tier. NOT a failure.
  if (!input.credential) {
    if (!input.affiliation) return { ok: true, operator: { ...UNVERIFIED } };
    // An affiliation with no operator credential vouches for nothing, but it was still
    // presented — so it must hold up structurally or it is a failed claim.
    const aff = await verifyAffiliation(input.affiliation, deps.resolvePublicKey, { subject: input.agentDid, relation: "operates", now });
    return aff.valid
      ? { ok: true, operator: { ...UNVERIFIED } }
      : { ok: false, operator: { ...UNVERIFIED }, reason: "affiliation_invalid", detail: aff.reason };
  }

  const cred = input.credential;
  const claims = cred.credentialSubject;

  // O1 — the registrar's signature. A self-claimed "verified" dies here.
  const sig = await verifyOperatorCredential(cred, deps.resolvePublicKey);
  if (!sig.valid) {
    return { ok: false, operator: { ...UNVERIFIED }, reason: "operator_signature_invalid", detail: sig.reason };
  }

  // O2 — the ∧ link. Skipped only when the credential is about THIS agent directly
  // (the registrar verified the agent's own operator identity, no org in between).
  let org: string | undefined;
  if (claims.id !== input.agentDid) {
    if (!input.affiliation) {
      // Nothing linking this agent to the verified operator ⇒ floor, don't fail.
      return { ok: true, operator: { ...UNVERIFIED } };
    }
    const aff = await verifyAffiliation(input.affiliation, deps.resolvePublicKey, {
      subject: input.agentDid,
      org: claims.id,
      relation: "operates",
      now,
    });
    if (!aff.valid) {
      return { ok: false, operator: { ...UNVERIFIED }, reason: "affiliation_invalid", detail: aff.reason };
    }
    org = claims.id;
  }

  // O3 — published revocation (offline). A struck-off operator must not keep trading
  // on a mandate that snapshotted its level at issuance.
  if (claims.status && deps.checkStatus) {
    const st = await deps.checkStatus(claims.status);
    if (st.revoked) {
      return {
        ok: false,
        operator: { ...UNVERIFIED },
        reason: "operator_revoked",
        ...(st.reason ? { revocationReason: st.reason } : {}),
        detail: `operator verification revoked${st.reason ? `: ${st.reason}` : ""}`,
      };
    }
  }

  // O4 — identity decays: domain rungs re-challenge, `verified` refreshes.
  if (claims.expiresAt && now > new Date(claims.expiresAt)) {
    return { ok: false, operator: { ...UNVERIFIED }, reason: "operator_expired", detail: `expired at ${claims.expiresAt}` };
  }

  return {
    ok: true,
    operator: {
      level: claims.level,
      method: claims.method,
      subjectType: claims.subjectType,
      registrar: claims.registrar,
      verifiedAt: claims.verifiedAt,
      ...(org ? { org } : {}),
    },
  };
}
