import { eq, and, isNull } from "drizzle-orm";
import type { Database } from "./db/client.js";
import { accessTokens, sessions } from "./db/schema.js";
import { generateOpaqueToken, hashToken } from "./crypto.js";
import type { PrincipalKind } from "./roles.js";

const DEFAULT_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes - deliberately short

export class TokenValidationError extends Error {
  constructor(
    public reason: "not_found" | "expired" | "revoked" | "session_revoked" | "already_rotated",
  ) {
    super(`Token invalid: ${reason}`);
    this.name = "TokenValidationError";
  }
}

/** Issues a brand-new token tied to a (freshly created or existing) session. */
export async function issueAccessToken(
  db: Database,
  input: {
    principalId: string;
    principalKind: PrincipalKind;
    deviceId: string | null;
    sessionId: string;
    ttlMs?: number;
  },
): Promise<{ raw: string; tokenId: string; expiresAt: Date }> {
  const { raw, hash } = generateOpaqueToken();
  const expiresAt = new Date(Date.now() + (input.ttlMs ?? DEFAULT_TOKEN_TTL_MS));

  const [token] = await db
    .insert(accessTokens)
    .values({
      tokenHash: hash,
      principalId: input.principalId,
      principalKind: input.principalKind,
      deviceId: input.deviceId,
      sessionId: input.sessionId,
      expiresAt,
      rotatedFromTokenId: null,
    })
    .returning();

  return { raw, tokenId: token!.id, expiresAt };
}

/**
 * Rotates a token: atomically claims the old token as "being rotated" by
 * flipping revokedAt from NULL to now() in a single conditional UPDATE,
 * then issues the replacement only if that claim succeeded.
 *
 * Why this matters: if we instead did "read old token, check it's not
 * revoked, then write revoked=true" as two separate steps, two concurrent
 * rotation requests (e.g. a client retrying after a slow network response)
 * could both pass the check before either writes - producing two "new"
 * tokens from the same parent, one of which the legitimate client never
 * sees. That's exactly the kind of bug that's invisible in manual testing
 * and shows up under real concurrent load. The WHERE revoked_at IS NULL
 * clause makes Postgres itself the referee: only one UPDATE can ever match
 * that row and return it, so only one caller can ever get a non-empty
 * result back, regardless of timing.
 */
export async function rotateAccessToken(
  db: Database,
  oldTokenRaw: string,
  ttlMs?: number,
): Promise<{ raw: string; tokenId: string; expiresAt: Date }> {
  const oldHash = hashToken(oldTokenRaw);

  const claimed = await db
    .update(accessTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(accessTokens.tokenHash, oldHash), isNull(accessTokens.revokedAt)))
    .returning();

  const oldToken = claimed[0];

  if (!oldToken) {
    // Either the token never existed, or it was already revoked/rotated -
    // possibly by a concurrent call that won the race a moment ago.
    const existing = await db.query.accessTokens.findFirst({
      where: eq(accessTokens.tokenHash, oldHash),
    });
    if (!existing) throw new TokenValidationError("not_found");
    throw new TokenValidationError("already_rotated");
  }

  const next = await issueAccessToken(db, {
    principalId: oldToken.principalId,
    principalKind: oldToken.principalKind as PrincipalKind,
    deviceId: oldToken.deviceId,
    sessionId: oldToken.sessionId,
    ttlMs,
  });

  await db
    .update(accessTokens)
    .set({ rotatedFromTokenId: oldToken.id })
    .where(eq(accessTokens.id, next.tokenId));

  return next;
}

export async function revokeAccessToken(db: Database, tokenRaw: string) {
  const hash = hashToken(tokenRaw);
  await db
    .update(accessTokens)
    .set({ revokedAt: new Date() })
    .where(eq(accessTokens.tokenHash, hash));
}

export interface ValidatedToken {
  tokenId: string;
  principalId: string;
  principalKind: PrincipalKind;
  deviceId: string | null;
  sessionId: string;
}

/**
 * Validates a raw token: checks existence, revocation, expiry, AND that
 * the parent session hasn't been revoked - a revoked session invalidates
 * every token under it even if the token itself was never individually
 * revoked. This is the single check every other service should call
 * before trusting a request.
 */
export async function validateAccessToken(db: Database, tokenRaw: string): Promise<ValidatedToken> {
  const hash = hashToken(tokenRaw);

  // Fetch regardless of revoked status first, so we can report the real
  // reason for rejection rather than collapsing "revoked" into "not_found".
  const token = await db.query.accessTokens.findFirst({
    where: eq(accessTokens.tokenHash, hash),
  });
  if (!token) throw new TokenValidationError("not_found");
  if (token.revokedAt) throw new TokenValidationError("revoked");

  if (token.expiresAt.getTime() < Date.now()) {
    throw new TokenValidationError("expired");
  }

  const session = await db.query.sessions.findFirst({
    where: eq(sessions.id, token.sessionId),
  });
  if (!session || session.status === "revoked") {
    throw new TokenValidationError("session_revoked");
  }

  return {
    tokenId: token.id,
    principalId: token.principalId,
    principalKind: token.principalKind as PrincipalKind,
    deviceId: token.deviceId,
    sessionId: token.sessionId,
  };
}