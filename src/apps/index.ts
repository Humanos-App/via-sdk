/** v0.4 §13 — capabilities and apps: the protocol parts of the connector router. */
export { capabilityDigest, capabilityIssues, capabilityVersionIssues, capabilityInputSchema, capabilityDefinition, capabilityCarries, capabilityFillIssues, isCapabilityName } from "./capability.js";
export type { ViaCapability, CapabilityParam } from "./capability.js";
export { APP_MANIFEST_TYP, appDigest, appManifestIssues, signAppManifest, readAppManifest } from "./manifest.js";
export type { ViaApp, AppImplements, AppRules, AppManifestContext } from "./manifest.js";
