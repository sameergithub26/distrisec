import { eq } from "drizzle-orm";
import type { Database } from "./db/client.js";
import { devices } from "./db/schema.js";
import type { PrincipalKind } from "./roles.js";

/**
 * Registers a device the first time it's seen, or returns + touches the
 * existing record if the fingerprint is already known. New devices start
 * "unknown" trust - something else (an MDM enrollment check, an admin
 * action, etc.) has to explicitly upgrade them to "trusted".
 */
export async function registerOrTouchDevice(
  db: Database,
  input: { fingerprint: string; ownerPrincipalId: string; ownerPrincipalKind: PrincipalKind },
) {
  const existing = await db.query.devices.findFirst({
    where: eq(devices.fingerprint, input.fingerprint),
  });

  if (existing) {
    const [updated] = await db
      .update(devices)
      .set({ lastSeenAt: new Date() })
      .where(eq(devices.id, existing.id))
      .returning();
    return updated!;
  }

  const [device] = await db
    .insert(devices)
    .values({
      fingerprint: input.fingerprint,
      ownerPrincipalId: input.ownerPrincipalId,
      ownerPrincipalKind: input.ownerPrincipalKind,
      trustLevel: "unknown",
    })
    .returning();
  return device!;
}

export async function setDeviceTrustLevel(
  db: Database,
  deviceId: string,
  trustLevel: "trusted" | "unmanaged" | "unknown",
) {
  const [updated] = await db
    .update(devices)
    .set({ trustLevel })
    .where(eq(devices.id, deviceId))
    .returning();
  return updated!;
}

export async function getDeviceById(db: Database, deviceId: string) {
  return db.query.devices.findFirst({ where: eq(devices.id, deviceId) });
}
