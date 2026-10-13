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
    description: { text: "Act within the pinned action.", lang: "en", author: "issuer" },
    enforcement: "rules",
  });
  // Securing model (spec §0.5): the mandate carries ONE content-bound STAMP; the
  // ISSUE/ACCEPT consents are standalone content-bound VIAEvents in the chain.
  mandate = stampMandate(mandate, { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });

  issueEvent = signEvent(
    buildEvent({ subject: mandate.id, event: "ISSUE", issuer: orgDid, credential: mandate, previousEvent: null }),
    { privateKey: org.privateKey, verificationMethod: vm(orgDid) },
  );
  acceptEvent = signEvent(
    buildEvent({
      subject: mandate.id,
      event: "ACCEPT",
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

describe("verify flow (§0.8)", () => {
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
  // @invariant §17.4: the VP path has no step-up ceremony, so a mandate that asks the person on
  // every call is refused here rather than allowed without the co-sign.
  it("refuses a mandate that asks the person on every call", async () => {
    const everyCall = stampMandate(
      buildMandate({
        subjectOrg: orgDid,
        grantor: userDid,
        authorizedDIDs: [verifierDid],
        action: buildActionReference(action, "https://api.humanos.tech/actions/pay-1"),
        userParams: wrapUserParamsWithAction(action, { maxAmount: 500, categories: ["books"] }),
        validFrom: "2026-01-01T00:00:00.000Z",
        description: { text: "Act within the pinned action.", lang: "en", author: "issuer" },
        enforcement: "rules",
        stepUp: { triggers: ["mandate"] },
      }),
      { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) },
    );
    const asks = buildPresentation({ credential: everyCall, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });
    const r = await verify({ presentation: asks, executionParams: { amount: 1, category: "books" } }, deps());
    expect(r).toMatchObject({ decision: "deny", reason: "stepup_required", enforcement: "rules" });
  });
  // @invariant §19.5: a spent grant was used exactly as agreed, not withdrawn — the issuer's record
  // says so, and the deny says so too.
  it("denies a spent Bounded-Use grant as max_executions_reached, not as revoked", async () => {
    const r = await verify(
      { presentation: vp, executionParams: { amount: 1, category: "books" } },
      { ...deps(), loadCredentialRecord: async () => ({ status: "REVOKED" as const, exhausted: true }) },
    );
    expect(r).toMatchObject({ decision: "deny", reason: "max_executions_reached" });
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
        description: { text: "Act within the pinned action.", lang: "en", author: "issuer" },
        enforcement: "rules",
      }),
      { privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) },
    );
    const boundVp = buildPresentation({ credential: bound, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vm(VIA_PLATFORM_DID) });
    const r = await verify({ presentation: boundVp, executionParams: { amount: 1, category: "books" } }, deps());
    expect(r).toMatchObject({ decision: "deny", reason: "pop_invalid", enforcement: "rules" });
  });

  // @invariant §20.3: a verifier returns `enforcement` on its decision — a denial as much as an
  // allow, and whichever step denied, so the signed VERIFICATION_DENIED can always record it (§2.0).
  it.each([
    ["an unauthorized verifier", "verifier_not_authorized", { verifier: { did: "did:web:intruder.tld" } }, {}],
    ["a revoked credential", "credential_revoked", { loadCredentialRecord: async () => ({ status: "REVOKED" as const }) }, {}],
    ["a spent grant", "max_executions_reached", { loadCredentialRecord: async () => ({ status: "REVOKED" as const, exhausted: true }) }, {}],
    ["a mandate not yet valid", "not_yet_valid", { loadCredentialRecord: async () => ({ ...activeRecord, validFrom: "2027-01-01T00:00:00.000Z" }) }, {}],
    ["an expired mandate", "expired", { loadCredentialRecord: async () => ({ ...activeRecord, validUntil: "2026-01-02T00:00:00.000Z" }) }, {}],
    ["an action that cannot be loaded", "action_not_found", { loadActionVersion: async () => null }, {}],
    ["invalid execution params", /^execution_params_invalid:/, {}, { amount: "lots" }],
    ["a failed rule", "rule_failed", {}, { amount: 999 }],
  ])("a denial states the mandate's enforcement — %s", async (_why, reason, over, params) => {
    const r = await verify(
      { presentation: vp, executionParams: { amount: 1, category: "books", ...params } },
      { ...deps(), ...over },
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toEqual(typeof reason === "string" ? reason : expect.stringMatching(reason));
    expect(r.enforcement).toBe("rules");
  });
  it("an allow states the mandate's enforcement", async () => {
    const r = await verify({ presentation: vp, executionParams: { amount: 1, category: "books" } }, deps());
    expect(r).toMatchObject({ decision: "allow", enforcement: "rules" });
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
    // Nothing in a presentation that is not Humanos's is a mandate to speak for (§20.3).
    expect(r.enforcement).toBeUndefined();
  });
});

