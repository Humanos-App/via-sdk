/**
 * §20 — the mandate description, its author, and what `enforcement` decides.
 *
 * The rules under test are the ones that make the field worth signing: the words are the grant on
 * a mandate that pins no action, they are DERIVED on one that does, the party who wrote them is
 * recorded, and text the requester wrote may narrow authority but never widen it.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  DESCRIPTION_MAX_LENGTH,
  adoptDescription,
  buildMandate,
  descriptionOf,
  enforcementOf,
  evaluateRules,
  generateEd25519Key,
  generateViaDID,
  mayWidenAuthority,
  stampMandate,
  validateDescription,
  validateMandateDescription,
  verifyStamp,
  type Ed25519KeyPair,
  type Mandate,
  type MandateDescription,
} from "../src/index.js";

const AGENT = "did:web:humanos.tech:agent:2f8b6c41-9d37-4e5a-8b02-6c1d9e7a4f35";
const ACTION = { id: "urn:via:action:slack", digestSRI: "sha256-x", location: "https://api/action" };
const words = (over: Partial<MandateDescription> = {}): MandateDescription => ({
  text: "Draft replies in my inbox. Never send one without showing me first.",
  lang: "en",
  author: "grantor",
  ...over,
});

const mandateInput = (over: Record<string, unknown> = {}) => ({
  subjectOrg: generateViaDID("org", { uuid: "o" }),
  grantor: generateViaDID("user", { uuid: "u" }),
  authorizedDIDs: ["did:web:verifier.example"],
  validFrom: "2026-09-22T00:00:00.000Z",
  description: words(),
  ...over,
});

describe("validateDescription (§20.1)", () => {
  it.each([
    ["empty text — %s", { text: "   " }, "description_empty"],
    ["no language — %s", { lang: "" }, "description_lang_missing"],
    ["an author outside the three — %s", { author: "platform" }, "description_author_invalid"],
    ["more words than the reader holds — %s", { text: "x".repeat(DESCRIPTION_MAX_LENGTH + 1) }, "description_too_long"],
  ])("refuses %s", (_case, over, reason) => {
    const r = validateDescription(words(over as Partial<MandateDescription>));
    expect(r).toEqual({ ok: false, reason });
  });

  // @invariant The bound is refused at issuance. Truncating at READ is the attack it exists for:
  // the decisive clause falls off the end while the signature stays valid.
  it("accepts a description exactly at the bound", () => {
    expect(validateDescription(words({ text: "x".repeat(DESCRIPTION_MAX_LENGTH) })).ok).toBe(true);
  });
});

describe("enforcementOf (§20.3)", () => {
  it("reads the field when it is there", () => {
    expect(enforcementOf({ enforcement: "semantic" } as Mandate)).toBe("semantic");
  });

  it.each([
    ["an action means its rules govern — %s", { action: ACTION }, "rules"],
    ["no action means nothing does — %s", {}, "none"],
  ])("derives for a pre-§20 artifact: %s", (_case, m, expected) => {
    expect(enforcementOf(m as Mandate)).toBe(expected);
  });
});

describe("the two validity rules (§20.3)", () => {
  it("refuses a grant whose words are missing", () => {
    expect(validateMandateDescription({ enforcement: "none" } as Mandate)).toEqual({
      ok: false,
      reason: "description_required",
    });
  });

  it("refuses prose written beside rules that govern", () => {
    const m = { action: ACTION, enforcement: "rules", description: words({ author: "grantor" }) } as Mandate;
    expect(validateMandateDescription(m)).toEqual({ ok: false, reason: "description_author_not_issuer" });
  });

  it("accepts an issuer-derived description on a rules mandate", () => {
    const m = { action: ACTION, enforcement: "rules", description: words({ author: "issuer" }) } as Mandate;
    expect(validateMandateDescription(m).ok).toBe(true);
  });

  // A mandate issued before §20 existed carries no description and must keep verifying (v0.2-new §13).
  it("leaves a pre-§20 rules mandate alone", () => {
    expect(validateMandateDescription({ action: ACTION } as Mandate).ok).toBe(true);
  });
});

describe("adoptDescription — the adoption bar (§20.2)", () => {
  const draft = { text: "Read #random once a day.", lang: "en" };

  it("keeps words the agent drafted and the person accepted as the AGENT's", () => {
    const d = adoptDescription({ draft, proposedBy: AGENT, accepted: "Read #random once a day." });
    expect(d).toMatchObject({ author: "agent", proposedBy: { actor: AGENT, adopted: true } });
  });

  it("makes them the grantor's once the grantor edits them", () => {
    const d = adoptDescription({ draft, proposedBy: AGENT, accepted: "Read #random once a day, mornings only." });
    expect(d.author).toBe("grantor");
  });

  // @invariant Whitespace is not an edit. Treating it as one would hand an agent grantor-authorship
  // for the price of a trailing space in a textarea.
  it("does not count whitespace as an edit", () => {
    const d = adoptDescription({ draft, proposedBy: AGENT, accepted: "  Read #random once a day.  " });
    expect(d.author).toBe("agent");
  });
});

describe("mayWidenAuthority — the narrowing rule (§20.2)", () => {
  it.each([
    ["grantor", true],
    ["issuer", true],
    ["agent", false],
  ])("words written by the %s may widen: %s", (author, expected) => {
    expect(mayWidenAuthority(words({ author: author as MandateDescription["author"] }))).toBe(expected);
  });
});

describe("buildMandate (§20)", () => {
  let platform: Ed25519KeyPair;
  beforeAll(() => {
    platform = generateEd25519Key();
  });

  it("refuses at issuance rather than producing an invalid artifact", () => {
    expect(() => buildMandate(mandateInput({ description: undefined }) as never)).toThrow(
      /description_required/,
    );
  });

  it("writes enforcement on every mandate, derived when the caller says nothing", () => {
    expect(buildMandate(mandateInput() as never).credentialSubject.mandate.enforcement).toBe("none");
    const policy = buildMandate(
      mandateInput({ action: ACTION, description: words({ author: "issuer" }) }) as never,
    );
    expect(policy.credentialSubject.mandate.enforcement).toBe("rules");
  });

  it("declares semantic review in the signed manifest — it is critical, not advisory (§19.4)", () => {
    const m = buildMandate(mandateInput({ enforcement: "semantic" }) as never);
    expect(m.credentialSubject.mandate.extensions).toContain("semanticReview");
  });

  it("carries the initiator and the pinned version into the signed body", () => {
    const m = buildMandate(
      mandateInput({
        action: { ...ACTION, version: 5 },
        description: words({ author: "issuer" }),
        initiator: { actor: AGENT, role: "execution", at: "2026-09-22T10:01:37.220Z" },
      }) as never,
    );
    expect(m.credentialSubject.mandate.initiator).toMatchObject({ actor: AGENT, role: "execution" });
    expect(m.credentialSubject.mandate.action?.version).toBe(5);
  });

  it("content-binds the words: editing one character invalidates the STAMP", async () => {
    const m = stampMandate(buildMandate(mandateInput() as never), {
      privateKey: platform.privateKey,
      verificationMethod: "did:web:humanos.tech#key-1",
    });
    expect((await verifyStamp(m, () => platform.publicKey)).valid).toBe(true);

    const tampered = structuredClone(m);
    tampered.credentialSubject.mandate.description!.text = "Draft replies in my inbox. Send them too.";
    expect((await verifyStamp(tampered, () => platform.publicKey)).valid).toBe(false);
    expect(descriptionOf(m)?.author).toBe("grantor");
  });
});

describe("rule applicability — appliesTo / requires (S13)", () => {
  const rules = [
    { name: "allowed_tools", description: "Only the tools you allowed", conditions: [],
      expression: "executionParams.tool in userParams.allowed_tools" },
    { name: "allowed_channels", description: "A channel you allowed", conditions: [],
      appliesTo: ["slack_send_message"], requires: ["channel_id"],
      expression: "executionParams.channel_id in userParams.allowed_channels" },
  ];
  const ctx = (executionParams: Record<string, unknown>) => ({
    userParams: { allowed_tools: ["slack_send_message", "slack_add_list_record"], allowed_channels: ["C1"] },
    executionParams,
  });

  it("denies a governed call that omits the parameter the rule constrains", () => {
    const r = evaluateRules(rules, ctx({ tool: "slack_send_message" }));
    expect(r.decision).toBe("deny");
    expect(r.evaluations[1]).toMatchObject({ rule: "allowed_channels", result: "fail" });
    expect(r.evaluations[1]?.reason).toContain("required_param_missing:channel_id");
  });

  // The permissive guard this replaces — `!has(executionParams.channel_id) || …` — answered ALLOW
  // here, which is how a person's allowlist bound only the calls that volunteered a channel.
  it("records a rule the call is outside of as skipped, and lets the call through", () => {
    const r = evaluateRules(rules, ctx({ tool: "slack_add_list_record", list_id: "L1" }));
    expect(r.decision).toBe("allow");
    expect(r.evaluations[1]).toMatchObject({ rule: "allowed_channels", result: "skip" });
  });

  it("still evaluates a governed call that carries the parameter", () => {
    expect(evaluateRules(rules, ctx({ tool: "slack_send_message", channel_id: "C1" })).decision).toBe("allow");
    expect(evaluateRules(rules, ctx({ tool: "slack_send_message", channel_id: "C9" })).decision).toBe("deny");
  });
});
