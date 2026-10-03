import { eq } from "drizzle-orm";
import type { Database } from "./db/client.js";
import { sessions } from "./db/schema.js";
import type { PrincipalKind } from "./roles.js";

export async function createSession(
  db: Database,
  input: {
    principalId: string;
    principalKind: PrincipalKind;
    deviceId: string | null;
    country: string | null;
  },
) {
  const [session] = await db
    .insert(sessions)
    .values({
      principalId: input.principalId,
      principalKind: input.principalKind,
      deviceId: input.deviceId,
      lastKnownCountry: input.country,
      status: "active",
    })
    .returning();
  return session!;
}

export async function touchSession(db: Database, sessionId: string, country: string | null) {
  const [updated] = await db
    .update(sessions)
    .set({
      lastActivityAt: new Date(),
      ...(country ? { lastKnownCountry: country } : {}),
    })
    .where(eq(sessions.id, sessionId))
    .returning();
  return updated;
}

export async function setSessionRiskScore(db: Database, sessionId: string, riskScore: number) {
  const [updated] = await db
    .update(sessions)
    .set({ currentRiskScore: riskScore })
    .where(eq(sessions.id, sessionId))
    .returning();
  return updated;
}

export async function requireStepUp(db: Database, sessionId: string) {
  const [updated] = await db
    .update(sessions)
    .set({ status: "step_up_required" })
    .where(eq(sessions.id, sessionId))
    .returning();
  return updated;
}

export async function reactivateSession(db: Database, sessionId: string) {
  const [updated] = await db
    .update(sessions)
    .set({ status: "active" })
    .where(eq(sessions.id, sessionId))
    .returning();
  return updated;
}

/** Revoking a session is the "kill switch" - any tokens issued under it
 * should be checked against this status on every validation (see tokens.ts). */
export async function revokeSession(db: Database, sessionId: string) {
  const [updated] = await db
    .update(sessions)
    .set({ status: "revoked" })
    .where(eq(sessions.id, sessionId))
    .returning();
  return updated;
}

export async function getSessionById(db: Database, sessionId: string) {
  return db.query.sessions.findFirst({ where: eq(sessions.id, sessionId) });
}
