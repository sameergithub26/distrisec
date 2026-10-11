import { createSecurityEvent, type AccessRequestContext, type PolicyDecision } from "@distrisec/shared";
import {
  type Database as IdentityDatabase,
  validateAccessToken,
  touchSession,
  requireStepUp,
  setSessionRiskScore,
  TokenValidationError,
} from "@distrisec/identity";
import type { Policy } from "@distrisec/policy-engine";
import { decide } from "@distrisec/policy-engine";
import { type Database as AuditDatabase, appendAuditEntry } from "@distrisec/audit-log";
import type { EventBus } from "@distrisec/event-pipeline";
import type { RiskAssessment, RiskScorer } from "@distrisec/risk-engine";
import { buildAccessRequestContext, type IncomingRequest } from "./context-builder.js";

export interface GatewayOptions {
  /**
   * If provided, the gateway publishes a SecurityEvent for every decision
   * about an IDENTIFIED principal. Optional so existing callers keep
   * working unchanged.
   *
   * Events for failed-token requests are deliberately NOT published yet:
   * they all carry the same "unknown principal" sentinel, so a detector
   * would see many unrelated bad tokens as ONE person and could, for
   * example, raise a bogus "impossible travel". They're still written to
   * the audit log. Publishing them properly needs the TokenValidationError
   * improvement noted below.
   */
  eventBus?: EventBus;
  /**
   * If provided, the gateway asks it for a risk score on every request and
   * uses THAT as `risk.score` in policy evaluation, instead of whatever
   * number happens to be stored on the session. The score is also saved
   * back to the session and recorded in the audit entry.
   *
   * Note the one-request lag: a detector flag is raised when an event is
   * published, which happens AFTER that request's decision. So a flag
   * influences the NEXT request's score, not the one that triggered it.
   * (Closing that gap would mean evaluating detectors before deciding.)
   */
  riskScorer?: RiskScorer;
}

export interface GatewayResult {
  decision: PolicyDecision;
  context: AccessRequestContext | null;
  /** The risk assessment used for this decision, if a riskScorer was supplied. */
  risk: RiskAssessment | null;
}

/**
 * Sentinel principal ID used for audit entries produced when a token
 * fails validation for ANY reason (not found, expired, revoked, or the
 * session behind it was revoked). The audit log schema requires a real
 * UUID in principalId - it can't be null, deliberately, because "who did
 * this" should never be an optional field on a security log, even when
 * the honest answer is "we don't know."
 *
 * Known limitation, noted rather than fixed here: validateAccessToken's
 * TokenValidationError currently doesn't carry the principal id it found
 * along the way, even for the expired/revoked cases where the token row
 * (and therefore its owner) WAS found before failing. That means today
 * every failed-token audit entry uses this same sentinel, which makes
 * "which real user's token keeps failing" harder to mine out of the log
 * than it should be. Extending TokenValidationError to optionally carry a
 * known principalId is a small, contained change to tokens.ts.
 */
const UNKNOWN_PRINCIPAL_ID = "00000000-0000-0000-0000-000000000000";

/**
 * The single entry point every caller (an API route, a CLI, the simulator
 * we'll build later) should go through to get an access decision. This
 * function owns the full request lifecycle:
 *
 *   1. validate the token (identity package)
 *   2. build the request context (this package's context-builder)
 *   3. evaluate policy against that context (policy-engine package)
 *   4. apply the decision's side effects (mark session step_up_required;
 *      record this request as the session's new "last known country")
 *   5. append a tamper-evident audit entry recording what happened
 *      (audit-log package) - on EVERY path, including a token that fails
 *      validation entirely, since a failed access attempt is itself
 *      security-relevant and must not go unrecorded
 *   6. optionally publish a SecurityEvent to the event bus so detectors
 *      can react (event-pipeline package)
 *
 * Step 4's ordering is the one thing in this function that's easy to get
 * wrong, so it's worth being explicit about it:
 *
 * We build the context (step 2) and evaluate policy (step 3) BEFORE
 * calling touchSession to record the new country. If we updated the
 * session's country first, then `previousCountry` in the context would
 * already equal the new country by the time the policy engine saw it -
 * the "country != previous_country" rule would never be able to fire,
 * because by definition the two values would already match. The session
 * only gets updated to reflect "this is now the known country" AFTER the
 * decision has already been made using the OLD country as the basis for
 * comparison. See gateway.test.ts for a test that pins this down
 * explicitly, because it's exactly the kind of bug that silently breaks a
 * security control while every "happy path" test still passes.
 */
export async function evaluateAccessRequest(
  identityDb: IdentityDatabase,
  auditDb: AuditDatabase,
  policy: Policy,
  tokenRaw: string,
  request: IncomingRequest,
  options: GatewayOptions = {},
): Promise<GatewayResult> {
  let validated;
  try {
    validated = await validateAccessToken(identityDb, tokenRaw);
  } catch (err) {
    if (err instanceof TokenValidationError) {
      // Any problem with the token itself - expired, revoked, the whole
      // session revoked, or it never existed - collapses to a plain deny
      // at the gateway boundary. We deliberately do NOT distinguish these
      // reasons in the RETURNED decision, because telling an attacker WHY
      // their token didn't work ("expired" vs "revoked" vs "never
      // existed") is free reconnaissance information we have no reason to
      // hand out. The REAL reason still goes into the audit log below,
      // where only people who already have legitimate access to the audit
      // trail can see it - a very different audience than "whoever just
      // sent us a bad token."
      const decision: PolicyDecision = {
        effect: "deny",
        matchedRuleIds: [],
        reason: "Invalid token",
      };

      await appendAuditEntry(auditDb, {
        principalId: UNKNOWN_PRINCIPAL_ID,
        principalKind: "user",
        action: request.action,
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        result: "deny",
        reason: `Invalid token: ${err.reason}`,
        metadata: { ip: request.ip, country: request.country },
      });

      return { decision, context: null, risk: null };
    }
    throw err;
  }

  const baseContext = await buildAccessRequestContext(identityDb, validated, request);

  // If a risk scorer is configured, its score REPLACES the session's stored
  // one for this decision. The device trust level and roles come from the
  // freshly-built context, so the score reflects the principal's state
  // right now, not at login.
  let context = baseContext;
  let risk: RiskAssessment | null = null;
  if (options.riskScorer) {
    risk = options.riskScorer.assess(validated.principalId, {
      deviceTrustLevel: baseContext.deviceTrustLevel,
      roles: baseContext.principalRoles,
    });
    context = { ...baseContext, riskScore: risk.score };
  }

  const decision = decide(policy, context);

  if (decision.effect === "step_up") {
    await requireStepUp(identityDb, validated.sessionId);
  }

  // Record this request's country as the session's new baseline, AFTER
  // the decision was computed - see the big comment above for why this
  // ordering is load-bearing, not incidental.
  await touchSession(identityDb, validated.sessionId, request.country);

  if (risk) {
    await setSessionRiskScore(identityDb, validated.sessionId, risk.score);
  }

  await appendAuditEntry(auditDb, {
    principalId: validated.principalId,
    principalKind: validated.principalKind,
    action: request.action,
    resourceType: request.resourceType,
    resourceId: request.resourceId,
    result: decision.effect,
    reason: decision.reason,
    metadata: {
      matchedRuleIds: decision.matchedRuleIds,
      ip: request.ip,
      country: request.country,
      sessionId: validated.sessionId,
      deviceId: validated.deviceId,
      // Recorded so "why was this denied?" can be answered from the audit
      // trail alone: the score, its band, and what contributed to it.
      ...(risk
        ? {
            risk: {
              score: risk.score,
              band: risk.band,
              components: risk.components.map((c) => ({ name: c.name, value: c.value })),
            },
          }
        : {}),
    },
  });

  if (options.eventBus) {
    // Publish AFTER the audit entry is durably written: the audit log is
    // the source of truth, the bus is a notification about it. If the bus
    // or a subscriber fails, the decision and its audit record are already
    // safe - and a bus failure must never change an access decision, so
    // handler errors are returned by publish() rather than thrown.
    await options.eventBus.publish(
      createSecurityEvent({
        principalId: validated.principalId,
        sessionId: validated.sessionId,
        deviceId: validated.deviceId,
        action: request.action,
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        ip: request.ip,
        country: request.country,
        result: decision.effect === "step_up" ? "step_up_required" : decision.effect,
        riskScoreAtDecision: context.riskScore,
        metadata: { matchedRuleIds: decision.matchedRuleIds },
      }),
    );
  }

  return { decision, context, risk };
}