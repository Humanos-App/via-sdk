import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  generateViaDID,
  VIA_PLATFORM_DID,
  buildActionVersion,
  buildActionReference,
  wrapUserParamsWithAction,
  buildMandate,
  stampMandate,
  buildPresentation,
  verify,
  actionDigestSRI,
  actionPublishIssues,
  mandateMayPin,
  policyMayName,
  readsUserParams,
  constantsRead,
  evaluateRules,
  type ActionDetail,
  type Ed25519KeyPair,
  type VerifiablePresentation,
} from "../src/index.js";

/**
 * v0.3 §0.6.1–§0.6.3 — an ActionVersion says what it is `for`, a person's mandate or the organization's policy, and
 * any version may fix values as `constants`, which its rules read as `constants.<name>`.
 */

/** The organization's own cap: no person, so its limit is a constant. */
const CAP = buildActionVersion({
  $id: "urn:via:action:cap",
  version: "1",
  for: "policy",
  constants: { maxAmount: { type: "number", value: 5000, description: "the most one payment may be" } },
  executionParams: { amount: { type: "number" } },
  rules: [{
    name: "payment_cap",
    description: "A payment is at most €5,000",
    requires: ["amount"],
    conditions: [{ left: "executionParams.amount", operator: "<=", right: "constants.maxAmount" }],
  }],
});

describe("constants in a rule (§0.6.2, §0.6.3)", () => {
  // @invariant §0.6.2: a condition's operand may be `constants.<name>`, so a fixed value needs no literal.
  it("generates a condition over a constant, and evaluates it with the version's values", () => {
    expect(CAP.rules[0]!.expression).toBe("executionParams.amount <= constants.maxAmount");
    const ctx = (amount: number) => ({ userParams: {}, constants: { maxAmount: 5000 }, executionParams: { amount } });
    expect(evaluateRules(CAP.rules, ctx(40)).decision).toBe("allow");
    expect(evaluateRules(CAP.rules, ctx(9000)).decision).toBe("deny");
  });

  it("wraps a datetime constant as a parameter is", () => {
    const window = buildActionVersion({
      $id: "urn:via:action:window",
      version: "1",
      for: "policy",
      constants: { closes: { type: "datetime", value: "2026-12-31T00:00:00Z" } },
      executionParams: { at: { type: "datetime" } },
      rules: [{ name: "before_close", description: "Only before the window closes", conditions: [{ left: "executionParams.at", operator: "<", right: "constants.closes" }] }],
    });
    expect(window.rules[0]!.expression).toBe("timestamp(executionParams.at) < timestamp(constants.closes)");
  });

  // @invariant §0.6.1: a version without `for` or constants is the content it was — its digest does not move.
  it("writes neither field into a version that has none", () => {
    const plain = buildActionVersion({
      $id: "urn:via:action:plain",
      version: "1",
      userParams: { cap: { type: "number", required: true } },
      executionParams: { amount: { type: "number" } },
      rules: [{ name: "cap", description: "At most your cap", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.cap" }] }],
    });
    expect(Object.keys(plain)).not.toContain("for");
    expect(Object.keys(plain)).not.toContain("constants");
    // A mandate's version with no userParams still carries the empty map it always did.
    const noParams = buildActionVersion({
      $id: "urn:via:action:x",
      version: "1",
      executionParams: { a: { type: "number" }, b: { type: "number" } },
      rules: [{ name: "r", description: "d", conditions: [{ left: "executionParams.a", operator: "<=", right: "executionParams.b" }] }],
    });
    expect(noParams.userParams).toEqual({});
  });

  it("reads the constants an expression names from its parse tree", () => {
    expect(constantsRead('executionParams.amount <= constants.cap && constants["floor"] > 0')).toEqual(["cap", "floor"]);
    expect(constantsRead('"constants.cap" == executionParams.note')).toEqual([]);
  });
});

describe("what may be published (§0.6.1)", () => {
  it("accepts a policy action with constants, and a mandate action with constants beside its userParams", () => {
    expect(actionPublishIssues(CAP)).toEqual([]);
    // @invariant §0.6.1: any version may declare constants — a mandate's are terms the person sees as fixed.
    const claims = buildActionVersion({
      $id: "urn:via:action:claims",
      version: "1",
      for: "mandate",
      userParams: { maxAmount: { type: "number", required: true } },
      constants: { ceiling: { type: "number", value: 50000 } },
      executionParams: { amount: { type: "number", required: true } },
      rules: [
        { name: "your_cap", description: "At most the amount you set", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] },
        { name: "our_ceiling", description: "Never above €50,000", conditions: [{ left: "executionParams.amount", operator: "<=", right: "constants.ceiling" }] },
      ],
    });
    expect(actionPublishIssues(claims)).toEqual([]);
  });

  // @invariant §0.6.1: a `for` this SDK does not know is refused, never read as one of the two.
  it("refuses a `for` other than mandate or policy", () => {
    expect(actionPublishIssues({ ...CAP, for: "polcy" as never })).toEqual(['"for" is "polcy": it must be mandate or policy.']);
  });

  // @invariant §0.6.1: a policy action neither declares nor reads userParams — the policy runs it with none.
  it("refuses a policy action that declares userParams, or has a rule reading them in any form", () => {
    expect(actionPublishIssues({ ...CAP, userParams: { cap: { type: "number" } } })).toContain(
      "A policy action has no user params (cap): a policy runs with no person to set them. Make each one a constant.",
    );
    const whole = { ...CAP, rules: [{ ...CAP.rules[0]!, conditions: [], expression: '"vip" in userParams' }] };
    expect(actionPublishIssues(whole)).toContain('Rule "payment_cap" reads userParams, which a policy action has none of. Read a constant instead.');
    const inText = { ...CAP, rules: [{ ...CAP.rules[0]!, conditions: [], expression: 'executionParams.note != "userParams.cap" && executionParams.amount <= constants.maxAmount' }] };
    expect(actionPublishIssues(inText)).toEqual([]);
  });

  it("refuses a constant that is not a CEL identifier, not of its type, or not declared where a rule reads it", () => {
    expect(actionPublishIssues({ ...CAP, constants: { ...CAP.constants, "max-amount": { type: "number", value: 1 } } })).toContain(
      'Rename constant "max-amount": use only letters, digits and _, not starting with a digit, so a rule can read it.',
    );
    expect(actionPublishIssues({ ...CAP, constants: { maxAmount: { type: "number", value: "5000" } } }).join()).toMatch(/maxAmount/);
    const undeclared = { ...CAP, rules: [{ ...CAP.rules[0]!, conditions: [{ left: "executionParams.amount", operator: "<=" as const, right: "constants.cap" }], expression: "executionParams.amount <= constants.cap" }] };
    expect(actionPublishIssues(undeclared)).toContain('Rule "payment_cap" reads constants.cap, which this version does not declare. Add it, or change the rule.');
  });
});

describe("who may use a version (§16.4, §21.1)", () => {
  const legacy: Pick<ActionDetail, "for" | "userParams" | "rules"> = { userParams: {}, rules: [{ name: "r", description: "d", conditions: [], expression: "executionParams.amount <= 100" }] };
  // @invariant §16.4: no mandate pins a version written for the policy; one without `for` may be pinned.
  it("lets a mandate pin any version but a policy's", () => {
    expect(mandateMayPin(CAP)).toBe(false);
    expect(mandateMayPin({ for: "mandate" })).toBe(true);
    expect(mandateMayPin({})).toBe(true);
  });

  // @invariant §21.1: the policy names no version written for a mandate, and one without `for` only when it reads no
  // userParams.
  it("lets the policy name a policy's version, or one without `for` that reads no userParams", () => {
    expect(policyMayName(CAP)).toBe(true);
    expect(policyMayName(legacy)).toBe(true);
    expect(policyMayName({ ...legacy, for: "mandate" })).toBe(false);
    expect(policyMayName({ ...legacy, userParams: { cap: { type: "number" } } })).toBe(false);
    expect(policyMayName({ ...legacy, rules: [{ name: "r", description: "d", conditions: [], expression: "executionParams.amount <= userParams.cap" }] })).toBe(false);
  });

  it("reads userParams from the parse tree, the whole map included, never a string's text", () => {
    expect(readsUserParams("executionParams.amount <= userParams.cap")).toBe(true);
    expect(readsUserParams('"vip" in userParams')).toBe(true);
    expect(readsUserParams('executionParams.note == "userParams"')).toBe(false);
    expect(readsUserParams("executionParams.amount <=")).toBeNull();
  });
});

describe("constants on the presentation path (§0.8)", () => {
  let platform: Ed25519KeyPair;
  let vp: VerifiablePresentation;
  const verifierDid = "did:web:fidelidade.pt";
  const vm = `${VIA_PLATFORM_DID}#key-1`;
  const claims = buildActionVersion({
    $id: "urn:via:action:claims-2",
    version: "1",
    for: "mandate",
    userParams: { maxAmount: { type: "number", required: true, description: "claim cap" } },
    constants: { ceiling: { type: "number", value: 1000, description: "the most any claim may be" } },
    executionParams: { amount: { type: "number", required: true } },
    rules: [
      { name: "your_cap", description: "At most the amount you set", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] },
      { name: "our_ceiling", description: "Never above €1,000", conditions: [{ left: "executionParams.amount", operator: "<=", right: "constants.ceiling" }] },
    ],
  });

  beforeAll(() => {
    platform = generateEd25519Key();
    const mandate = stampMandate(
      buildMandate({
        subjectOrg: generateViaDID("org", { uuid: "org-c" }),
        grantor: generateViaDID("user", { uuid: "user-c" }),
        authorizedDIDs: [verifierDid],
        action: buildActionReference(claims, "https://api.humanos.tech/actions/claims-2"),
        userParams: wrapUserParamsWithAction(claims, { maxAmount: 5000 }),
        validFrom: "2026-01-01T00:00:00.000Z",
        description: { text: "Claims within the pinned action.", lang: "en", author: "issuer" },
        enforcement: "rules",
      }),
      { privateKey: platform.privateKey, verificationMethod: vm },
    );
    vp = buildPresentation({ credential: mandate, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vm });
  });

  // @invariant §0.6.3: the verifier evaluates a mandate's rules with the pinned version's constants — the person's
  // €5,000 stops at the organization's €1,000.
  it("caps a person's limit at the version's constant", async () => {
    const deps = {
      verifier: { did: verifierDid },
      resolvePublicKey: async () => platform.publicKey,
      loadCredentialRecord: async () => ({ status: "ACTIVE" as const, validFrom: "2026-01-01T00:00:00.000Z" }),
      loadActionVersion: async (id: string) => (id === claims.$id ? claims : null),
      now: new Date("2026-06-23T00:00:00.000Z"),
    };
    expect((await verify({ presentation: vp, executionParams: { amount: 800 } }, deps)).decision).toBe("allow");
    const over = await verify({ presentation: vp, executionParams: { amount: 2000 } }, deps);
    expect(over.decision).toBe("deny");
    expect(over.evaluations.find((e) => e.rule === "our_ceiling")?.result).toBe("fail");
    expect(actionDigestSRI(claims)).toBe(buildActionReference(claims, "x").digestSRI);
  });
});
