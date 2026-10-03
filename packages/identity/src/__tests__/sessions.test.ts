import { describe, it, expect } from "vitest";
import { getDb } from "../db/client.js";
import { createUser } from "../users.js";
import {
  createSession,
  requireStepUp,
  reactivateSession,
  revokeSession,
  getSessionById,
} from "../sessions.js";

describe("session lifecycle", () => {
  it("starts active on creation", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "sess@acme.com", displayName: "Sess", password: "pw12345678" });
    const session = await createSession(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      country: "IN",
    });
    expect(session.status).toBe("active");
  });

  it("can be marked step_up_required and later reactivated", async () => {
    // This models e.g. "country changed mid-session" - we don't want to
    // kill the session outright (that'd log the user out entirely), we
    // want to pause it until they re-authenticate, then let it resume.
    const db = getDb();
    const user = await createUser(db, { email: "stepup@acme.com", displayName: "StepUp", password: "pw12345678" });
    const session = await createSession(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      country: "IN",
    });

    const paused = await requireStepUp(db, session.id);
    expect(paused?.status).toBe("step_up_required");

    const resumed = await reactivateSession(db, session.id);
    expect(resumed?.status).toBe("active");
  });

  it("revocation is terminal and reflected in a fresh lookup", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "term@acme.com", displayName: "Term", password: "pw12345678" });
    const session = await createSession(db, {
      principalId: user.id,
      principalKind: "user",
      deviceId: null,
      country: "IN",
    });

    await revokeSession(db, session.id);
    const fetched = await getSessionById(db, session.id);
    expect(fetched?.status).toBe("revoked");
  });
});
