/**
 * VIA Protocol SDK (v0.2)
 *
 * Functions-only library implementing spec/via-protocol-spec-v0.2.md:
 * Ed25519 / `eddsa-jcs-2022` / W3C VC 2.0. No HTTP, DB, or KMS — all I/O is injected.
 */

// Config & types
export * from "./types.js";
// Spec-version identity + detection (constants come via types.js; functions here)
export { detectSpecVersion, isSupportedSpecVersion, type DetectedSpecVersion } from "./version.js";

// Crypto
export {
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  base58Encode,
  base58Decode,
  toMultibaseBase58,
  fromMultibaseBase58,
} from "./crypto/encoding.js";
export { canonicalizeRFC8785 } from "./crypto/canonicalize.js";
export { sha256, sha256Hex, computeSRI, verifySRI, actionVersionPinSRI } from "./crypto/digest.js";
export { viaUrn, type ViaUrnType } from "./urn.js";
export {
  generateEd25519Key,
  publicKeyFromPrivate,
  signRaw,
  signMultibase,
  verifyRaw,
  verifyMultibase,
  encodePublicKeyMultibase,
  decodePublicKeyMultibase,
  generateDIDKey,
  type Ed25519KeyPair,
  type DIDKeyPair,
} from "./crypto/ed25519.js";
export {
  generateP256Key,
  signES256,
  verifyES256,
  jwkThumbprint,
  cleanPublicJwk,
  type Jwk,
  type P256KeyPair,
} from "./crypto/p256.js";
export {
  createDataIntegrityProof,
  verifyDataIntegrityProof,
  type DataIntegrityProof,
  type ProofPurpose,
  EVENT_TYPES,
  EventTypeEnum,
  type EventType,
  type LifecycleAction,
  type CreateProofParams,
} from "./crypto/proof.js";

// DID
export {
  ACTOR_TYPES,
  generateViaDID,
  generateDomainDID,
  normalizeDomain,
  didFromUrl,
  didWebToUrl,
  parseDidWeb,
  verificationMethodId,
  getKeyId,
  verifierDomainOf,
  VIA_PLATFORM_DID,
  VIA_PLATFORM_DOMAIN,
  type ActorType as DidActorSegment,
  type ParsedDidWeb,
} from "./did/web.js";
export {
  buildDidDocument,
  findVerificationMethod,
  isAuthorizedFor,
  resolveVerificationKey,
  DID_CONTEXT,
  type DidDocument,
  type VerificationMethod,
} from "./did/document.js";

// Action & CEL
export * from "./action/types.js";
export {
  validateParams,
  validateExecutionParams,
  validateUserParams,
  wrapUserParamsWithAction,
  unwrapUserParamValues,
  type WrappedUserParam,
} from "./action/execution-params.js";
export { operatorsByType, buildTypeResolver, generateCelExpression } from "./action/cel.js";
export {
  buildActionVersion,
  actionDigestSRI,
  buildActionReference,
  verifyActionReference,
  type BuildActionVersionInput,
} from "./action/build.js";
export {
  evaluateRule,
  evaluateRules,
  validateCelExpression,
  CEL_EXPRESSION_MAX_LENGTH,
  type CelContext,
  type RuleEvaluation,
  type EvaluationResult,
} from "./cel/evaluate.js";

// Mandate
export {
  buildMandate,
  normalizeMandateStepUp,
  // §20 — the mandate description (spec §20.1–§20.3)
  buildEvidence,
  MEDIA_TYPE_PATTERN,
  stampMandate,
  verifyStamp,
  addProof,
  verifyMandateProofs,
  validateMaxExecutions,
  EXT_MAX_EXECUTIONS,
  EXT_SEMANTIC_REVIEW,
  unsupportedCriticalExtension,
  MAX_EXECUTIONS_REACHED,
  type BuildMandateInput,
  type BuildEvidenceInput,
  type StampSigner,
  type MandateSigner,
  type MandateProofCheck,
  type ResolvePublicKey,
} from "./mandate/build.js";
export type {
  DescriptionAuthor,
  Enforcement,
  MandateDescription,
  MandateInitiator,
  MandateStepUp,
  StepUpTrigger,
} from "./types.js";
export {
  DESCRIPTION_MAX_LENGTH,
  validateDescription,
  validateMandateDescription,
  enforcementOf,
  enforcementFitsShape,
  descriptionOf,
  adoptDescription,
  mayWidenAuthority,
  type DescriptionProblem,
  type AdoptInput,
} from "./mandate/description.js";

// Credential-level signer (§0.5.4) — the SDK owns HOW the securing STAMP is made.
export {
  signCredentialProof,
  type CredentialProof,
  type CredentialProofSigner,
} from "./credential/proof.js";

// Events — the unified VIAEvent primitive (spec §0.5)
export {
  buildEvent,
  signEvent,
  verifyEvent,
  walkEventChain,
  eventChainLink,
  auditEventChain,
  buildChainedEvent,
  buildIssuanceEvents,
  credentialDigestOf,
  type BuildEventInput,
  type BindableCredential,
  type EventAudit,
  type ChainAudit,
  type EventSigner,
  type BuildChainedEventInput,
  type IssuanceParty,
  type IssuanceInput,
  type IssuanceResult,
} from "./event/build.js";

// Status
export {
  createBitstring,
  setBit,
  getBit,
  encodeList,
  decodeList,
  MINIMUM_LIST_LENGTH,
} from "./status/bitstring.js";
export {
  StatusList,
  buildCredentialStatusEntry,
  checkCredentialStatus,
  type StatusPurpose,
  type CredentialStatusCheck,
} from "./status/status.js";

// Presentation
export {
  buildPresentation,
  verifyPresentation,
  generateChallenge,
  domainMatches,
  type BuildPresentationInput,
  type VerifiedPresentation,
  type GenerateChallengeContext,
} from "./presentation/vp.js";

export {
  buildSdJwtMandate,
  presentSdJwt,
  verifySdJwtPresentation,
  VIA_VCT,
  SD_JWT_TYP,
  type BuildSdJwtMandateInput,
  type PresentSdJwtInput,
  type VerifiedSdJwt,
} from "./presentation/sd-jwt.js";
export {
  buildSdJwtSignal,
  redactSdJwtSignal,
  verifySdJwtSignal,
  VIA_SIGNAL_VCT,
} from "./signal/sd-jwt.js";
export type { ViaSignalBody, BuildSdJwtSignalInput, VerifiedSdJwtSignal } from "./signal/sd-jwt.js";

// Verify
export {
  verify,
  type VerifyDeps,
  type VerifyResult,
  type VerifyInput,
  type CredentialRecord,
} from "./verify/verify.js";


// Agent Binding (§16)
export {
  type Runtime,
  type RuntimeAttestation,
  type Assurance,
  type Binding,
  type Root,
  type AgentReasonCode,
  type CustodyRef,
  type BoundKey,
  boundKeyVerifiedAtMs,
  isAssurance,
  isBinding,
  BINDINGS,
  type ConfinementEvidence,
  type ConfinementResult,
  type NitroCa,
  ASSURANCE_RANK,
  assuranceRank,
  meets,
} from "./agent/types.js";
export {
  actionHash,
  buildPoP,
  algForKey,
  allowedPopAlgs,
  decodePoP,
  verifyPoPSignature,
  type PopPayload,
  type DecodedPoP,
} from "./agent/pop.js";

// Agent Binding (§16) — registration/attestation (§16.5)
export {
  validateCustody,
  NO_ROOTS,
  type PinnedRoots,
  validateCoseAttestation,
  coseKeyToJwk,
  validateWebauthnAttestation,
  readAttestationNonce,
  type DescribeKey,
  type KeyDescription,
} from "./agent/attestation.js";
export {
  registerChallenge,
  registerAgentKey,
  createRegChallengeStore,
  type RegChallengeStore,
  type RegisterChallengeDeps,
  type RegisterChallenge,
  type RegisterAgentKeyInput,
  type RegisterAgentKeyDeps,
} from "./agent/registration.js";

// Agent Binding (§16) — constraints (structured → CEL) + the verify path (A1–A8)
export {
  assertNoUnverifiedClientRefs,
  unverifiedClientRefs,
  UNVERIFIED_CLIENT_FIELDS,
  constraintToRule,
  constraintsToRules,
  agentReasonForRule,
  type Constraint,
} from "./agent/constraints.js";
export {
  verifyAgentBinding,
  verifyAgentDirect,
  projectAccreditation,
  ACCREDITATION_ENV_FIELDS,
  type AgentEnv,
  type PopCheckInput,
  type PopCheckDeps,
  type PopCheckResult,
  type AgentDirectDeps,
  type AgentDirectResult,
  type SemanticReviewInput,
  type SemanticReviewVerdict,
  type CredentialRecordLike,
} from "./agent/verify.js";

// Agent Binding (§16) — audit (§16.9, signed VIAEvents). `EventSigner` now lives in event/build.js.
export {
  buildVerificationEvent,
} from "./agent/audit.js";

// Operator Verification (§18 proposal) — the identity axis
export {
  accreditationRank,
  meetsAccreditation,
  ACCREDITATION_RANK,
  ACCREDITATION_METHODS,
  claimValidUntil,
  type AccreditationLevel,
  type AccreditationMethod,
  type SubjectType,
  type AffiliationRelation,
  type AccreditationReasonCode,
  type AccreditationRevocationReason,
  type AccreditationClaims,
  type AccreditationEnv,
} from "./operator/types.js";
export {
  type BuildAccreditationInput,
  buildAccreditation,
  buildAffiliation,
  buildRegulatory,
  verifyAffiliation,
  type AffiliationSigner,
  type BuildAffiliationInput,
  type BuildRegulatoryInput,
} from "./operator/affiliation.js";
export {
  verifyAccreditation,
  type AccreditationVerifyInput,
  type AccreditationVerifyDeps,
  type AccreditationVerifyResult,
} from "./operator/verify.js";

// Grantor Binding (§17)
export {
  enrollGrantor,
  grantorBindingMethod,
  grantorTermsDigest,
  mandateBodyTermsDigest,
  verifyGrantorAssertion,
  buildGrantorBinding,
  buildOtpGrantorBinding,
  type GrantorBinding,
  type WebauthnGrantorBinding,
  type OtpGrantorBinding,
  type GrantorChannel,
  type LegacyGrantorBinding,
  type GrantorReasonCode,
  type GrantorTerms,
  type WebauthnAssertion,
} from "./grantor/binding.js";
export { verifyWebauthnAssertion, type WebauthnAssertionInput } from "./crypto/webauthn.js";

// VIAActor — the actor axis (v0.3 §3–§5)
export {
  foldActorChain,
  actorSummaryFloor,
  ACCREDITATION_METHODS_BY_LEVEL,
  chooseSurvivor,
  ACTOR_FOLD_VERSION,
  resolveSuccession,
  resolvePinnedKeysAcrossMerge,
  resolvePinnedKeys,
  // v0.3 §3.6c — `MERGED`: build the claim from the absorbed actor, and check one against it.
  buildMergeClaim,
  checkMergeClaim,
  type MergeClaim,
  type MergedKey,
  foldActorRecord,
  auditActorRecord,
  projectAgentContext,
  ACTOR_EVENT_TYPES,
  // The authority for which subject class an event kind carries — a credential URN or an actor
  // DID. Consumers persisting events branch on this (the platform keys `credentialId` vs
  // `subjectDid` off it), so it has to be reachable as a VALUE, not just a type.
  EVENT_SCOPE,
  type EventScope,
  type ActorRecordResult,
  type ActorEventType,
  type ActorType,
  type ActorStatus,
  type ActorKeyStatus,
  type ActorKeyState,
  type AttestationRef,
  type BootstrapAnchor,
  type ViaActorSubject,
  type ViaActorRecord,
  type ActorChainPosition,
  type ActorFoldResult,
  type ActorAudit,
} from "./actor/model.js";

