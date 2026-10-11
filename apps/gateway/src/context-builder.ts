import type { AccessRequestContext } from "@distrisec/shared";
import {
  type Database,
  type ValidatedToken,
  getPrincipalRoleNames,
  getDeviceById,
  getSessionById,
} from "@distrisec/identity";

export interface IncomingRequest {
  resourceType: string;
  resourceId: string;
  action: string;
  ip: string;
  country: string | null;
}

/**
 * Builds the AccessRequestContext the policy engine needs, by combining:
 *  - the already-validated token (who is making this request, and under
 *    which session/device)
 *  - a fresh role lookup (roles can change between requests - we must
 *    never cache this on the token itself, or a revoked role would stay
 *    in effect until the token's natural expiry)
 *  - the device's CURRENT trust level (same reasoning - an admin
 *    downgrading a device's trust should take effect on the very next
 *    request, not wait for a new token)
 *  - the session's PREVIOUS country, read before this request's country
 *    is recorded anywhere - see the big comment in gateway.ts for why the
 *    ORDER this happens in relative to updating the session matters a lot.
 *
 * This function does not look at risk scoring yet (risk-engine comes
 * later in the project) - for now it just passes through whatever risk
 * score is currently stored on the session, defaulting to 0.
 */
export async function buildAccessRequestContext(
  db: Database,
  validated: ValidatedToken,
  request: IncomingRequest,
): Promise<AccessRequestContext> {
  const [roles, device, session] = await Promise.all([
    getPrincipalRoleNames(db, validated.principalId),
    validated.deviceId ? getDeviceById(db, validated.deviceId) : Promise.resolve(undefined),
    getSessionById(db, validated.sessionId),
  ]);

  if (!session) {
    // Shouldn't happen in practice - validateAccessToken already confirmed
    // the session exists and isn't revoked - but we don't trust that
    // invariant blindly here, since this function might get called from
    // somewhere else later that skips that check.
    throw new Error(`Session ${validated.sessionId} not found while building request context`);
  }

  return {
    principalId: validated.principalId,
    principalRoles: roles,
    deviceId: validated.deviceId,
    deviceTrustLevel: device?.trustLevel ?? null,
    resourceType: request.resourceType,
    resourceId: request.resourceId,
    action: request.action,
    ip: request.ip,
    country: request.country,
    previousCountry: session.lastKnownCountry,
    riskScore: session.currentRiskScore,
    timestamp: new Date().toISOString(),
  };
}
