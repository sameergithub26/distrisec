import { describe, it, expect } from "vitest";
import { getDb } from "../db/client.js";
import { createUser } from "../users.js";
import { createSession, revokeSession } from "../sessions.js";
import {
  issueAccessToken,
  validateAccessToken,
  rotateAccessToken,
  revokeAccessToken,
  TokenValidationError,
} from "../tokens.js";

/** Helper: create a user + session, the common setup every token test needs. */
async function setupPrincipalAndSession(db: ReturnType<typeof getDb>, email: string) {
  const user = await createUser(db, { email, displayName: "Test User", password: "pw12345678" });
  const session = await createSession(db, {
    principalId: user.id,
    principalKind: "user",
    deviceId: null,
    country: "IN",
  });
  return { user, session };
}

describe("token issuance and basic validation", () => {
  it("a freshly issued token validates successfully", async () => {
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "fresh@acme.com");

    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    const validated = await validateAccessToken(db, token.raw);
    expect(validated.principalId).toBe(user.id);
    expect(validated.sessionId).toBe(session.id);
  });

  it("an unknown token string is rejected as not_found", async () => {
    const db = getDb();
    await expect(validateAccessToken(db, "this-token-was-never-issued")).rejects.toMatchObject({
      reason: "not_found",
    });
  });

  it("an explicitly revoked token is rejected as revoked", async () => {
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "revoke-single@acme.com");
    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    await revokeAccessToken(db, token.raw);

    await expect(validateAccessToken(db, token.raw)).rejects.toMatchObject({ reason: "revoked" });
  });
});

describe("edge case: expired tokens", () => {
  it("a token issued with a TTL in the past is rejected as expired", async () => {
    // Why "in the past" rather than "wait for a real token to expire":
    // sleeping in a test suite to wait out a real 15-minute TTL would make
    // this test take 15 minutes to run, which nobody would ever actually
    // wait for - so instead we issue a token whose expiry is already
    // behind us. This tests the exact same code path (the expiresAt
    // comparison in validateAccessToken) without the wait.
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "expired@acme.com");

    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
      ttlMs: -1000, // expired one second before it was even issued
    });

    await expect(validateAccessToken(db, token.raw)).rejects.toMatchObject({ reason: "expired" });
  });

  it("a token issued with a short-but-valid TTL still works immediately", async () => {
    // Guards against an off-by-one in the expiry comparison that would
    // reject valid tokens too eagerly.
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "shortlived@acme.com");

    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
      ttlMs: 2000,
    });

    const validated = await validateAccessToken(db, token.raw);
    expect(validated.tokenId).toBe(token.tokenId);
  });
});

describe("edge case: revoked sessions cascade to their tokens", () => {
  it("revoking a session invalidates a token that was never individually revoked", async () => {
    // This is the "kill switch" property: an admin or an automated
    // response to a detected attack should be able to say "kill this
    // session" ONCE and have every token under it die, without having to
    // enumerate and revoke each token individually (which would also race
    // against new tokens being issued/rotated in the meantime).
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "cascade@acme.com");

    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    // token is fine on its own right now
    await validateAccessToken(db, token.raw);

    await revokeSession(db, session.id);

    await expect(validateAccessToken(db, token.raw)).rejects.toMatchObject({
      reason: "session_revoked",
    });
  });

  it("a session revocation also kills a token that was issued AFTER the revocation check started conceptually, i.e. any token under a revoked session, full stop", async () => {
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "cascade2@acme.com");
    await revokeSession(db, session.id);

    // Issuing a token under an already-revoked session is a slightly odd
    // thing to do in practice (the gateway shouldn't do this), but the
    // validation layer should refuse to trust it regardless of how it
    // got issued - defense in depth.
    const token = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    await expect(validateAccessToken(db, token.raw)).rejects.toMatchObject({
      reason: "session_revoked",
    });
  });
});

describe("edge case: rotation races", () => {
  it("rotating a token invalidates the old one and the new one works", async () => {
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "rotate@acme.com");
    const original = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    const rotated = await rotateAccessToken(db, original.raw);

    expect(rotated.raw).not.toBe(original.raw);
    await expect(validateAccessToken(db, original.raw)).rejects.toMatchObject({ reason: "revoked" });
    const validated = await validateAccessToken(db, rotated.raw);
    expect(validated.tokenId).toBe(rotated.tokenId);
  });

  it("rotating an already-rotated token fails cleanly instead of succeeding twice", async () => {
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "double-rotate@acme.com");
    const original = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    await rotateAccessToken(db, original.raw);

    // Rotating the SAME raw token a second time must fail - if it
    // succeeded, we'd have created a second "child" token from an
    // already-dead parent, which should never be reachable.
    await expect(rotateAccessToken(db, original.raw)).rejects.toMatchObject({
      reason: "already_rotated",
    });
  });

  it("concurrent rotation of the same token: exactly one caller wins, the other gets a clean error", async () => {
    // This fires two rotation calls for the SAME token at the same time
    // with Promise.all (no await in between) and asserts exactly one
    // succeeds. See the walkthrough above for why this test alone can't
    // be trusted to CATCH the bug (timing-dependent), but it documents
    // and locks in the correct behavior of the current, atomic implementation.
    const db = getDb();
    const { user, session } = await setupPrincipalAndSession(db, "race@acme.com");
    const original = await issueAccessToken(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      sessionId: session.id,
    });

    const results = await Promise.allSettled([
      rotateAccessToken(db, original.raw),
      rotateAccessToken(db, original.raw),
    ]);

    const succeeded = results.filter((r) => r.status === "fulfilled");
    const failed = results.filter((r) => r.status === "rejected");

    expect(succeeded).toHaveLength(1);
    expect(failed).toHaveLength(1);

    const failure = (failed[0] as PromiseRejectedResult).reason;
    expect(failure).toBeInstanceOf(TokenValidationError);
    expect(failure.reason).toBe("already_rotated");
  });
});
