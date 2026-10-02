import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  VIA_PLATFORM_DID,
  generateViaDID,
  buildActionVersion,
  buildActionReference,
  wrapUserParamsWithAction,
  buildMandate,
  stampMandate,
  verifyStamp,
  buildEvent,
  signEvent,
  verifyEvent,
  walkEventChain,
  canonicalizeRFC8785,
  computeSRI,
  buildPresentation,
  verifyPresentation,
  verify,
  StatusList,
  type ViaMandateCredential,
  type ViaEvent,
  type VerifiablePresentation,
  type Ed25519KeyPair,
  type CredentialRecord,
} from "../src/index.js";

let platform: Ed25519KeyPair, org: Ed25519KeyPair, user: Ed25519KeyPair;
let orgDid: string, userDid: string;
const verifierDid = "did:web:fidelidade.pt";
let registry: Record<string, Uint8Array>;
let action: ReturnType<typeof buildActionVersion>;
let mandate: ViaMandateCredential;
let issueEvent: ViaEvent, acceptEvent: ViaEvent;
let vp: VerifiablePresentation;

const resolvePublicKey = async (vmId: string): Promise<Uint8Array> => {
  const k = registry[vmId];
  if (!k) throw new Error(`unknown key: ${vmId}`);
  return k;
};
const vm = (did: string) => `${did}#key-1`;
const activeRecord: CredentialRecord = { status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" };

beforeAll(() => {
  platform = generateEd25519Key();
  org = generateEd25519Key();
  user = generateEd25519Key();
  orgDid = generateViaDID("org", { uuid: "org-1" });
  userDid = generateViaDID("user", { uuid: "user-1" });
  registry = {
    [vm(VIA_PLATFORM_DID)]: platform.publicKey,
    [vm(orgDid)]: org.publicKey,
    [vm(userDid)]: user.publicKey,
  };

  action = buildActionVersion({
    $id: "urn:via:action:pay-1",
    version: "1",
    target: { method: "POST", domain: "stripe.com", path: "/v1/payment_intents" },
    userParams: {
      maxAmount: { type: "number", required: true, description: "spend cap" },
      categories: { type: "array", items: "string", required: true },
    },
    executionParams: {
      amount: { type: "number", required: true },
      category: { type: "string", required: true },
    },
    rules: [
      { name: "amount_limit", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] },
      { name: "category_in", conditions: [{ left: "executionParams.category", operator: "in", right: "userParams.categories" }] },
    ],
  });

  mandate = buildMandate({
    subjectOrg: orgDid,
    grantor: userDid,
    authorizedDIDs: [verifierDid],
    action: buildActionReference(action, "https://api.humanos.tech/actions/pay-1"),
    userParams: wrapUserParamsWithAction(action, { maxAmount: 500, categories: ["books", "food"] }),
    validFrom: "2026-01-01T00:00:00.000Z",
  });
  // Securing model (spec §5): the mandate carries ONE content-bound STAMP; the
  // ISSUE/ACCEPT consents are standalone content-bound VIAEvents in the chain.
  mandate = stampMandate(mandate, { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });

  issueEvent = signEvent(
    buildEvent({ subject: mandate.id, event: "ISSUE", actor: orgDid, issuer: orgDid, credential: mandate, previousEvent: null }),
    { privateKey: org.privateKey, verificationMethod: vm(orgDid) },
  );
  acceptEvent = signEvent(
    buildEvent({
      subject: mandate.id,
      event: "ACCEPT",
      actor: userDid,
      issuer: userDid,
      credential: mandate,
      previousEvent: computeSRI(canonicalizeRFC8785(issueEvent)),
    }),
    { privateKey: user.privateKey, verificationMethod: vm(userDid) },
  );

  vp = buildPresentation({
    credential: mandate,
    holder: VIA_PLATFORM_DID,
    privateKey: platform.privateKey,
    verificationMethod: vm(VIA_PLATFORM_DID),
  });
});

describe("mandate securing STAMP + consent events", () => {
  it("mandate carries a single STAMP proof; verifyStamp valid + tamper detected", async () => {
    expect(Array.isArray(mandate.proof)).toBe(false);
    expect(mandate.proof?.event).toBe("STAMP");
    expect((await verifyStamp(mandate, resolvePublicKey)).valid).toBe(true);

    const tampered = { ...mandate, issuer: "did:web:evil" };
    expect((await verifyStamp(tampered, resolvePublicKey)).valid).toBe(false);
  });

  it("ISSUE/ACCEPT are standalone content-bound events that verify and chain", async () => {
    expect(issueEvent.credentialSubject.event).toBe("ISSUE");
    expect(acceptEvent.credentialSubject.event).toBe("ACCEPT");
    // content-bound: both carry the mandate digest, signed by different keys
    expect(issueEvent.credentialSubject.credentialDigest).toBe(acceptEvent.credentialSubject.credentialDigest);
    expect((await verifyEvent(issueEvent, resolvePublicKey, { credential: mandate })).valid).toBe(true);
    expect((await verifyEvent(acceptEvent, resolvePublicKey, { credential: mandate })).valid).toBe(true);

    // digest binding rejects a different credential body
    const bad = await verifyEvent(acceptEvent, resolvePublicKey, { credential: { ...mandate, issuer: "did:web:evil" } });
    expect(bad.valid).toBe(false);
    expect(bad.reason).toBe("credentialDigest_mismatch");

    // ordered chain: previousEvent must reference the prior event; reorder breaks it
    expect((await walkEventChain([issueEvent, acceptEvent])).ok).toBe(true);
    expect((await walkEventChain([acceptEvent, issueEvent])).ok).toBe(false);
  });
});

describe("presentation", () => {
  it("VP is Humanos-signed and verifies; embedded VC keeps its single STAMP proof (N18)", async () => {
    expect(vp.holder).toBe(VIA_PLATFORM_DID);
    expect(Array.isArray(vp.verifiableCredential.proof)).toBe(false);
    expect(vp.verifiableCredential.proof?.event).toBe("STAMP");
    const r = await verifyPresentation(vp, resolvePublicKey);
    expect(r.valid).toBe(true);
  });
});

describe("verify flow (§8)", () => {
  const deps = () => ({
    verifier: { did: verifierDid },
    resolvePublicKey,
    loadCredentialRecord: async () => activeRecord,
    loadActionVersion: async (id: string) => (id === action.$id ? action : null),
    now: new Date("2026-06-23T00:00:00.000Z"),
  });

  it("allows a compliant request", async () => {
    const r = await verify({ presentation: vp, executionParams: { amount: 100, category: "books" } }, deps());
    expect(r.decision).toBe("allow");
    expect(r.evaluations).toHaveLength(2);
  });
  it("denies over-limit (rule_failed)", async () => {
    const r = await verify({ presentation: vp, executionParams: { amount: 999, category: "books" } }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("rule_failed");
    expect(r.evaluations.find((e) => e.rule === "amount_limit")?.result).toBe("fail");
  });
  it("denies execution_params_invalid", async () => {
    const r = await verify({ presentation: vp, executionParams: { amount: "lots", category: "books" } }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/^execution_params_invalid:/);
  });
  it("denies an unauthorized verifier", async () => {
    const r = await verify(
      { presentation: vp, executionParams: { amount: 1, category: "books" } },
      { ...deps(), verifier: { did: "did:web:intruder.tld" } },
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("verifier_not_authorized");
  });
  it("denies a revoked credential", async () => {
    const r = await verify(
      { presentation: vp, executionParams: { amount: 1, category: "books" } },
      { ...deps(), loadCredentialRecord: async () => ({ status: "REVOKED" as const }) },
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("credential_revoked");
  });
  // @invariant §16.10: the VP path carries no proof-of-possession, so a mandate bound to agents fails
  // closed here — never verified on `authorizedDIDs` alone.
  it("refuses a mandate bound to agents on the VP path, which carries no PoP", async () => {
    const bound = stampMandate(
      buildMandate({
        subjectOrg: orgDid,
        grantor: userDid,
        authorizedDIDs: [verifierDid],
        authorizedAgents: [{ did: "did:web:humanos.tech:agent:a1", cnf: { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" } }, assurance: "pop", binding: "self", verifiedAt: "2026-01-01T00:00:00.000Z" } as never],
        action: buildActionReference(action, "https://api.humanos.tech/actions/pay-1"),
        userParams: wrapUserParamsWithAction(action, { maxAmount: 500, categories: ["books"] }),
        validFrom: "2026-01-01T00:00:00.000Z",
      }),
      { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) },
    );
    const boundVp = buildPresentation({ credential: bound, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });
    const r = await verify({ presentation: boundVp, executionParams: { amount: 1, category: "books" } }, deps());
    expect(r).toMatchObject({ decision: "deny", reason: "pop_invalid" });
  });

  it("rejects a VP not signed by Humanos", async () => {
    const forged = buildPresentation({
      credential: mandate,
      holder: VIA_PLATFORM_DID,
      privateKey: org.privateKey, // wrong signer
      verificationMethod: vm(VIA_PLATFORM_DID),
    });
    const r = await verify({ presentation: forged, executionParams: { amount: 1, category: "books" } }, deps());
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("vp_signature_invalid");
  });
});

