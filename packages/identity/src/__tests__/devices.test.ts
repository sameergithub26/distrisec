import { describe, it, expect } from "vitest";
import { getDb } from "../db/client.js";
import { createUser } from "../users.js";
import { registerOrTouchDevice, setDeviceTrustLevel } from "../devices.js";

describe("device identity", () => {
  it("a brand-new fingerprint registers as a new device with unknown trust", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "owner@acme.com", displayName: "Owner", password: "pw12345678" });

    const device = await registerOrTouchDevice(db, {
      fingerprint: "laptop-xyz",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });

    expect(device.trustLevel).toBe("unknown");
  });

  it("seeing the same fingerprint again returns the SAME device row, not a duplicate", async () => {
    // This is the whole point of fingerprint-based device identity: if the
    // same laptop logs in every day, we want ONE device record whose trust
    // level can accumulate over time, not a new row per login that always
    // starts back at "unknown".
    const db = getDb();
    const user = await createUser(db, { email: "repeat@acme.com", displayName: "Repeat", password: "pw12345678" });

    const first = await registerOrTouchDevice(db, {
      fingerprint: "shared-fingerprint",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });
    const second = await registerOrTouchDevice(db, {
      fingerprint: "shared-fingerprint",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });

    expect(second.id).toBe(first.id);
  });

  it("touching an existing device updates lastSeenAt", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "touch@acme.com", displayName: "Touch", password: "pw12345678" });

    const first = await registerOrTouchDevice(db, {
      fingerprint: "touch-fp",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });

    await new Promise((r) => setTimeout(r, 10));

    const second = await registerOrTouchDevice(db, {
      fingerprint: "touch-fp",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });

    expect(second.lastSeenAt.getTime()).toBeGreaterThan(first.lastSeenAt.getTime());
  });

  it("trust level can be explicitly escalated, e.g. after MDM enrollment", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "trust@acme.com", displayName: "Trust", password: "pw12345678" });
    const device = await registerOrTouchDevice(db, {
      fingerprint: "mdm-enrolled",
      ownerPrincipalId: user.id,
      ownerPrincipalKind: "user",
    });

    const trusted = await setDeviceTrustLevel(db, device.id, "trusted");
    expect(trusted.trustLevel).toBe("trusted");
  });
});
