/** v0.4 §14 — the context layer's protocol parts. */
export { KIND_LABELS, KIND_HINTS, isKind, isKindOrFamily, coversKind, labelOf, kindsOfLabel } from "./kinds.js";
export { TOKEN_OPEN, TOKEN_CLOSE, tokensIn, escapeTokenBrackets, type TokenFound } from "./tokens.js";
export { DEFAULT_REMOVE, NO_LAYER_CONTEXT, policyContextIssues, toolFillIssues, mayFill, unfilledTokens } from "./policy.js";
export type { PolicyContext, ToolFill, CallLayerContext, UnfilledToken } from "./policy.js";
