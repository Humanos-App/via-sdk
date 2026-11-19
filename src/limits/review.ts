/**
 * v0.4 §15.2 — the reviewer's two readings: a mandate's limits against its words before it is issued, and a call
 * against the words when it is made. One rule settles both, so the two moments cannot drift apart.
 */
import type { MandateDescription } from "../types.js";
import { policyToolFor } from "./policy.js";
import type { LimitRule, LimitsPolicy, MandateLimits, MandateTool, ReviewerPart } from "./types.js";

/** What a reviewer answers, at either moment. `unreadable`: in service, and unable to read THIS request. */
export interface ReviewAnswer {
  verdict: "entailed" | "not_entailed" | "escalate" | "unavailable" | "unreadable";
  reviewer?: { id: string; version?: string };
  reason?: string;
}

/** §15.2 — what a reviewer is asked before a mandate is issued: do these limits say what these words say? */
export interface LimitsReviewInput {
  description: MandateDescription;
  /** The tools the mandate would cover, each with the rules the requester wrote. */
  tools: Record<string, MandateTool>;
  /** The rules on every tool it covers. */
  rules?: LimitRule[];
  maxExecutions: number;
}

/** How a reading ended: it stands, with what the reviewer did; or it refuses, with §15.8's code. */
export type ReviewOutcome =
  | { ok: true; reviewed: ReviewerPart; reviewer?: { id: string; version?: string } }
  | { ok: false; reason: "semantic_denied" | "semantic_review" | "reviewer_unavailable"; reviewed?: ReviewerPart; reviewer?: { id: string; version?: string } };

/**
 * §15.2 — settle one answer of the reviewer, or its absence.
 *
 * - No answer — none deployed, or out of service — and the request stands without it: `unavailable`.
 * - A request it cannot read is refused, enforcing or not: only an outage passes, or a requester could choose when
 *   it goes unreviewed.
 * - A finding, or a request it could not settle, refuses where it enforces. Where it does not enforce yet, its
 *   answer is recorded and refuses nothing: `not_enforcing`.
 * - `required` — the policy marks the tool — makes it enforce, and lets nothing stand that it did not agree to.
 */
export function settleReview(answer: ReviewAnswer | undefined, mode: { enforces: boolean; required: boolean }): ReviewOutcome {
  const reviewer = answer?.reviewer;
  const named = reviewer ? { reviewer } : {};
  const enforces = mode.enforces || mode.required;
  if (answer?.verdict === "unreadable") return { ok: false, reason: "reviewer_unavailable", ...named };
  if (answer?.verdict === "not_entailed" && enforces) return { ok: false, reason: "semantic_denied", ...named };
  if (answer?.verdict === "escalate" && enforces) return { ok: false, reason: "semantic_review", ...named };
  const reviewed: ReviewerPart = !answer || answer.verdict === "unavailable" ? "unavailable" : answer.verdict === "entailed" ? "agreed" : "not_enforcing";
  if (mode.required && reviewed !== "agreed") return { ok: false, reason: "reviewer_unavailable", reviewed, ...named };
  return { ok: true, reviewed, ...named };
}

/** §15.2 — does the policy mark any tool this mandate would cover `reviewer: "required"`? */
export function reviewerRequiredFor(policy: Pick<LimitsPolicy, "tools">, limits: Pick<MandateLimits, "tools">): boolean {
  return Object.keys(limits.tools ?? {}).some((tool) => policyToolFor(policy, tool)?.entry.reviewer === "required");
}

export interface IssueReviewDeps {
  /** The reviewer's reading of limits against words. Absent, none is deployed. */
  reviewLimits?: (input: LimitsReviewInput) => ReviewAnswer | Promise<ReviewAnswer>;
  /** Does the reviewer enforce? `false` is the shadow phase. Default `true`. */
  reviewEnforces?: boolean;
}

/**
 * §15.2 — the reviewer before a mandate is issued: it compares the rules the requester wrote with the words the
 * person will read, and a mismatch refuses the request before the person sees it ("pay my phone bill" over "any
 * payment up to 5,000"). What it answers `reviewed` is what the mandate is then signed with
 * (`buildLimitsMandate`). A tool the policy marks `reviewer: "required"` gets no mandate without its agreement.
 */
export async function reviewMandateRequest(policy: Pick<LimitsPolicy, "tools">, limits: MandateLimits, deps: IssueReviewDeps = {}): Promise<ReviewOutcome> {
  const answer = deps.reviewLimits
    ? await deps.reviewLimits({ description: limits.description, tools: limits.tools, ...(limits.rules ? { rules: limits.rules } : {}), maxExecutions: limits.maxExecutions })
    : undefined;
  return settleReview(answer, { enforces: deps.reviewEnforces !== false, required: reviewerRequiredFor(policy, limits) });
}
