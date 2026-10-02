import type { ViaEvent } from "../src/types.js";
import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  buildAccreditation,
  buildAffiliation,
  verifyAccreditation,
  accreditationRank,
  meetsAccreditation,
  constraintsToRules,
  evaluateRules,
  agentReasonForRule,
  type Ed25519KeyPair,
  type Constraint,
} from "../src/index.js";

const AGENT = "did:web:agents.acme.com:atlas-7";
const ACME = "did:web:acme.com";
const REGISTRAR = "did:web:humanos.tech";
const VM_REG = `${REGISTRAR}#key-1`;
const VM_ACME = `${ACME}#key-1`;
const VM_EVIL = "did:web:evil.example#key-1";
const now = new Date("2026-07-23T12:00:00.000Z");

let registrar: Ed25519KeyPair, acme: Ed25519KeyPair, evil: Ed25519KeyPair;
const resolvePublicKey = async (vm: string) => {
  if (vm === VM_REG) return registrar.publicKey;
  if (vm === VM_ACME) return acme.publicKey;
  if (vm === VM_EVIL) return evil.publicKey;
  throw new Error(`unknown key ${vm}`);
};

beforeAll(() => {
  registrar = generateEd25519Key();
  acme = generateEd25519Key();
  evil = generateEd25519Key();
});

/** A registrar-signed "Acme is KYB-verified" — an ACCREDITED event on Acme's own chain (§18). */
function acmeVerified(over: Record<string, unknown> = {}): ViaEvent {
  const { id, status, ...rest } = over as { id?: string; status?: unknown };
  return buildAccreditation(
    {
      subject: (id as string) ?? ACME,
      level: "verified",
      method: "kyb-registry",
      subjectType: "organization",
      registrar: "humanos",
      verifiedAt: "2026-01-01T00:00:00.000Z",
      registrarDid: REGISTRAR,
      ...(rest as Record<string, never>),
      ...(status ? { status } : {}),
    } as never,
    { privateKey: registrar.privateKey, verificationMethod: VM_REG },
  );
}
/** Acme's own signature: "this agent operates for us" — the ∧ link. */
const acmeLink = (over: { subject?: string; org?: string; expiresAt?: string } = {}) =>
  buildAffiliation(
    { subject: over.subject ?? AGENT, org: over.org ?? ACME, relation: "operates", ...(over.expiresAt ? { expiresAt: over.expiresAt } : {}) },
    { privateKey: acme.privateKey, verificationMethod: VM_ACME },
  );

describe("operator ladder (ordinal)", () => {
  it("ranks unverified < domain < verified", () => {
    expect(accreditationRank("unverified")).toBeLessThan(accreditationRank("domain"));
    expect(accreditationRank("domain")).toBeLessThan(accreditationRank("verified"));
    expect(meetsAccreditation("verified", "domain")).toBe(true);
    expect(meetsAccreditation("domain", "verified")).toBe(false);
    expect(meetsAccreditation("domain", "domain")).toBe(true);
  });
});

describe("§18 O1–O4 + the ∧ composition", () => {
  it("honest: registrar credential ∧ org affiliation → verified, org attributed", async () => {
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: acmeVerified(), affiliation: acmeLink() }, { resolvePublicKey, now });
    expect(r.ok).toBe(true);
    expect(r.accreditation).toMatchObject({ level: "verified", method: "kyb-registry", subjectType: "organization", org: ACME });
  });

  // ── absence ≠ impersonation (the ❔ tier, must NOT be flagged) ──────────────
  it("no credential at all → unverified and PASSES (normal tier, not a failure)", async () => {
    const r = await verifyAccreditation({ agentDid: AGENT }, { resolvePublicKey, now });
    expect(r.ok).toBe(true);
    expect(r.accreditation.level).toBe("unverified");
    expect(r.reason).toBeUndefined();
  });

  it("verified credential but NO affiliation → floors at unverified, still passes", async () => {
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: acmeVerified() }, { resolvePublicKey, now });
    expect(r.ok).toBe(true);
    expect(r.accreditation.level).toBe("unverified"); // inheritance needs the org's own signature
    expect(r.reason).toBeUndefined();
  });

  // @invariant v0.3 §18.5 O1: a valid signature says who signed, not that the signer is a registrar.
  it("refuses an ACCREDITED the operator signed about itself — a correctly signed self-claim", async () => {
    const selfClaim = buildAccreditation(
      { subject: ACME, level: "verified", method: "kyb-registry", subjectType: "organization", registrar: "humanos", verifiedAt: "2026-01-01T00:00:00.000Z", registrarDid: ACME } as never,
      { privateKey: acme.privateKey, verificationMethod: VM_ACME },
    );
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: selfClaim, affiliation: acmeLink() }, { resolvePublicKey, now });
    expect(r).toMatchObject({ ok: false, reason: "accreditation_signature_invalid" });
    expect(r.accreditation.level).toBe("unverified");
  });

  it("counts an ACCREDITED signed by the environment's own registrar DID", async () => {
    const r = await verifyAccreditation(
      { agentDid: AGENT, accreditation: acmeVerified(), affiliation: acmeLink() },
      { resolvePublicKey, now, registrarDid: REGISTRAR },
    );
    expect(r.ok).toBe(true);
  });

  // ── the inheritance spoof: presented-and-failed ⇒ ⚠️ ───────────────────────
  it("affiliation signed by someone OTHER than the named org → affiliation_invalid", async () => {
    const forged = buildAffiliation(
      { subject: AGENT, org: ACME, relation: "operates" },
      { privateKey: evil.privateKey, verificationMethod: VM_EVIL }, // evil signs a claim about Acme
    );
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: acmeVerified(), affiliation: forged }, { resolvePublicKey, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("affiliation_invalid");
    expect(r.accreditation.level).toBe("unverified");
  });

  it("affiliation naming a different org than the credential → affiliation_invalid", async () => {
    const other = buildAffiliation(
      { subject: AGENT, org: "did:web:other.example", relation: "operates" },
      { privateKey: acme.privateKey, verificationMethod: VM_ACME },
    );
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: acmeVerified(), affiliation: other }, { resolvePublicKey, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("affiliation_invalid");
  });

  it("affiliation for a DIFFERENT agent → affiliation_invalid", async () => {
    const r = await verifyAccreditation(
      { agentDid: AGENT, accreditation: acmeVerified(), affiliation: acmeLink({ subject: "did:web:agents.acme.com:someone-else" }) },
      { resolvePublicKey, now },
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("affiliation_invalid");
  });

  // ── O1 forged accreditation ────────────────────────────────────────────────
  it("accreditation not signed by the registrar → operator_signature_invalid", async () => {
    // Signed with the wrong key while NAMING the registrar's verification method — a self-claimed
    // "verified". O1 resolves the vm it names and the signature does not check out.
    const selfClaimed = buildAccreditation(
      { subject: ACME, level: "verified", method: "kyb-registry", subjectType: "organization",
        registrar: "humanos", verifiedAt: "2026-01-01T00:00:00.000Z", registrarDid: REGISTRAR } as never,
      { privateKey: evil.privateKey, verificationMethod: VM_REG },
    );
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: selfClaimed, affiliation: acmeLink() }, { resolvePublicKey, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("accreditation_signature_invalid");
  });

  it("tampered level (domain → verified) invalidates the signature", async () => {
    const cred = acmeVerified({ level: "domain", method: "dns-challenge" });
    const tampered = { ...cred, credentialSubject: { ...cred.credentialSubject,
      accreditation: { ...(cred.credentialSubject as never as { accreditation: object }).accreditation, level: "verified" } } } as never;
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: tampered, affiliation: acmeLink() }, { resolvePublicKey, now });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("accreditation_signature_invalid");
  });

  // ── O3 revocation (verify-time, offline) ───────────────────────────────────
  it("revoked operator → operator_revoked with the reason", async () => {
    const cred = acmeVerified({
      status: { id: "https://status.humanos.tech/operator/list/1#42", type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "42", statusListCredential: "https://status.humanos.tech/operator/list/1" },
    });
    const r = await verifyAccreditation(
      { agentDid: AGENT, accreditation: cred, affiliation: acmeLink() },
      { resolvePublicKey, now, checkStatus: () => ({ revoked: true, reason: "struck_off" }) },
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("accreditation_revoked");
    expect(r.revocationReason).toBe("struck_off");
  });

  // ── O4 decay ───────────────────────────────────────────────────────────────
  it("expired credential → operator_expired (identity decays)", async () => {
    const r = await verifyAccreditation(
      { agentDid: AGENT, accreditation: acmeVerified({ level: "domain", method: "dns-challenge", expiresAt: "2026-04-01T00:00:00.000Z" }), affiliation: acmeLink() },
      { resolvePublicKey, now },
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("accreditation_expired");
  });

  it("expired affiliation → affiliation_invalid", async () => {
    const r = await verifyAccreditation(
      { agentDid: AGENT, accreditation: acmeVerified(), affiliation: acmeLink({ expiresAt: "2026-04-01T00:00:00.000Z" }) },
      { resolvePublicKey, now },
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("affiliation_invalid");
  });

  // @invariant v0.3 §18.4: an agent never holds standing of its own — it inherits its operator's.
  it("refuses a credential about the agent itself, even registrar-signed", async () => {
    const direct = acmeVerified({ id: AGENT, subjectType: "individual", method: "kyc-doc" });
    const r = await verifyAccreditation({ agentDid: AGENT, accreditation: direct }, { resolvePublicKey, now });
    expect(r).toMatchObject({ ok: false, reason: "accreditation_on_agent" });
    expect(r.accreditation.level).toBe("unverified");
  });
});

describe("§18 O5 — CEL floors over operator.*", () => {
  const CONSTRAINTS: Constraint[] = [
    { type: "accreditation_required", min: "verified", whenAmountAbove: 100 },
    { type: "accreditation_method_in", methods: ["kyb-registry", "eidas-high"] },
  ];
  const rules = constraintsToRules(CONSTRAINTS);
  const evalWith = (accreditation: Record<string, unknown>, amount: number) =>
    evaluateRules(rules, { userParams: {}, executionParams: { amount, action: "purchase" }, accreditation });

  it("verified operator clears the floor on a high-value action", () => {
    expect(evalWith({ level: "verified", method: "kyb-registry" }, 500).decision).toBe("allow");
  });

  it("unverified operator is blocked above the threshold → operator_insufficient", () => {
    const r = evalWith({ level: "unverified" }, 500);
    expect(r.decision).toBe("deny");
    const failed = r.evaluations.find((e) => e.result !== "pass")!;
    expect(agentReasonForRule(failed.rule)).toBe("accreditation_insufficient");
  });

  it("the floor does not fire below the threshold (guarded)", () => {
    // method still matches, and the level floor is guarded by amount
    expect(evalWith({ level: "unverified", method: "kyb-registry" }, 50).decision).toBe("allow");
  });

  it("a non-accepted method is rejected categorically", () => {
    const r = evalWith({ level: "verified", method: "dns-challenge" }, 500);
    expect(r.decision).toBe("deny");
    const failed = r.evaluations.find((e) => e.rule.startsWith("accreditation_method_in"))!;
    expect(failed.result).toBe("fail");
  });
});
