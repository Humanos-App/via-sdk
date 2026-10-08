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
import { verifyEvent } from "../event/build.js";
import { verifyAffiliation } from "./affiliation.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import type { ViaEvent, BitstringStatusListEntry } from "../types.js";
import { claimValidUntil } from "./types.js";
import type {
  AccreditationClaims,
  AccreditationEnv,
  AccreditationReasonCode,
  AccreditationRevocationReason,
} from "./types.js";

export interface AccreditationVerifyInput {
  /** The agent whose effective operator level we are computing. */
  agentDid: string;
  /**
   * The registrar-signed **`ACCREDITED` event** from the operator's own chain, if the agent
   * presents one (§18).
   *
   * An earlier draft took a standalone `VIAOperatorCredential`. It was dropped: a third party's
   * claim about an actor is a `VIAEvent` signed by that party — the shape `AFFILIATION` and
   * `REGULATORY` already use — so a second top-level artifact carried the same claims through a
   * second verify routine for no gain. One primitive, one signature check.
   */
  accreditation?: ViaEvent | null;
  /** The org-signed `operates` link, if the agent presents one. */
  affiliation?: ViaEvent | null;
}

export interface AccreditationVerifyDeps {
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>;
  /**
   * **O1** — the registrar: the Humanos platform DID whose signature makes an `ACCREDITED` count
   * (v0.3 §18.5: Humanos is the only registrar until v0.4 defines external ones). Defaults to
   * `did:web:humanos.tech`; an environment with its own platform DID (dev, stage) passes that.
   */
  registrarDid?: string;
  /**
   * **O3** — resolve the PUBLISHED status list entry (offline; no live registrar call,
   * preserving the agent-direct property §16.11). Omit to skip revocation checking.
   */
  checkStatus?: (entry: BitstringStatusListEntry) => Promise<{ revoked: boolean; reason?: AccreditationRevocationReason }> | { revoked: boolean; reason?: AccreditationRevocationReason };
  now?: Date;
}

export interface AccreditationVerifyResult {
  ok: boolean;
  /** Always present — floors at `unverified` rather than being absent. */
  accreditation: AccreditationEnv;
  reason?: AccreditationReasonCode;
  /** Human-readable detail behind `reason`. */
  detail?: string;
  /** Present on `operator_revoked` — underwriters need the *why*. */
  revocationReason?: AccreditationRevocationReason;
}

const UNVERIFIED: AccreditationEnv = { level: "unverified" };

/**
 * Run O1–O4 and compose the effective operator environment. O5 (the CEL floor) is
 * evaluated by the rule engine against the returned `operator` — exactly as A7 is
 * CEL over `agent.*`.
 */
export async function verifyAccreditation(input: AccreditationVerifyInput, deps: AccreditationVerifyDeps): Promise<AccreditationVerifyResult> {
  const now = deps.now ?? new Date();

  // Nothing presented → the normal unverified tier. NOT a failure.
  if (!input.accreditation) {
    if (!input.affiliation) return { ok: true, accreditation: { ...UNVERIFIED } };
    // An affiliation with no operator credential vouches for nothing, but it was still
    // presented — so it must hold up structurally or it is a failed claim.
    const aff = await verifyAffiliation(input.affiliation, deps.resolvePublicKey, { subject: input.agentDid, relation: "operates", now });
    return aff.valid
      ? { ok: true, accreditation: { ...UNVERIFIED } }
      : { ok: false, accreditation: { ...UNVERIFIED }, reason: "affiliation_invalid", detail: aff.reason };
  }

  const ev = input.accreditation;
  const cs = ev.credentialSubject as unknown as {
    id: string;
    accreditation?: AccreditationClaims & { status?: BitstringStatusListEntry };
  };
  const claims = cs.accreditation;
  if (!claims) {
    return { ok: false, accreditation: { ...UNVERIFIED }, reason: "accreditation_signature_invalid", detail: "event carries no accreditation" };
  }

  // O1 — the registrar's signature, through the SAME verify routine every other event uses. A
  // self-claimed "verified" dies here.
  const sig = await verifyEvent(ev, deps.resolvePublicKey);
  if (!sig.valid) {
    return { ok: false, accreditation: { ...UNVERIFIED }, reason: "accreditation_signature_invalid", detail: sig.reason };
  }
  // A valid signature says WHO signed, not that the signer is a registrar: an organization signing
  // "verified" about itself is a correctly signed lie. O1 binds the signer to the registrar.
  const registrar = deps.registrarDid ?? VIA_PLATFORM_DID;
  const signer = ev.proof?.verificationMethod?.split("#")[0];
  if (signer !== registrar) {
    return { ok: false, accreditation: { ...UNVERIFIED }, reason: "accreditation_signature_invalid", detail: `signed by ${signer ?? "nobody"}, not the registrar ${registrar}` };
  }
  // §18.4: an agent never holds standing of its own — it inherits its operator's. An `ACCREDITED`
  // about the agent itself is refused, never projected (the fold refuses it on an agent chain too).
  if (cs.id === input.agentDid) {
    return { ok: false, accreditation: { ...UNVERIFIED }, reason: "accreditation_on_agent" };
  }

  // O2 — the ∧ link: the operator the credential names, linked to this agent by its AFFILIATION.
  let org: string | undefined;
  {
    if (!input.affiliation) {
      // Nothing linking this agent to the verified operator ⇒ floor, don't fail.
      return { ok: true, accreditation: { ...UNVERIFIED } };
    }
    const aff = await verifyAffiliation(input.affiliation, deps.resolvePublicKey, {
      subject: input.agentDid,
      org: cs.id,
      relation: "operates",
      now,
    });
    if (!aff.valid) {
      return { ok: false, accreditation: { ...UNVERIFIED }, reason: "affiliation_invalid", detail: aff.reason };
    }
    org = cs.id;
  }

  // O3 — published revocation (offline). A struck-off operator must not keep trading
  // on a mandate that snapshotted its level at issuance.
  if (claims.status && deps.checkStatus) {
    const st = await deps.checkStatus(claims.status);
    if (st.revoked) {
      return {
        ok: false,
        accreditation: { ...UNVERIFIED },
        reason: "accreditation_revoked",
        ...(st.reason ? { revocationReason: st.reason } : {}),
        detail: `operator verification revoked${st.reason ? `: ${st.reason}` : ""}`,
      };
    }
  }

  // O4 — identity decays: domain rungs re-challenge, `verified` refreshes.
  const until = claimValidUntil(claims);
  if (until && now > new Date(until)) {
    return { ok: false, accreditation: { ...UNVERIFIED }, reason: "accreditation_expired", detail: `expired at ${until}` };
  }

  return {
    ok: true,
    accreditation: {
      level: claims.level,
      method: claims.method,
      subjectType: claims.subjectType,
      // v0.3 §18.2 — the registrar is who SIGNED the event (checked by O1 above), never a name the
      // claim states about itself.
      registrar,
      verifiedAt: claims.verifiedAt,
      ...(org ? { org } : {}),
    },
  };
}
