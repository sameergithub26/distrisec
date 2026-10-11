import { describe, it, expect } from "vitest";
import { sql, eq } from "drizzle-orm";
import { tokenize, parse, type Policy } from "@distrisec/policy-engine";
import {
  getDb as getIdentityDb,
  createUser,
  createRole,
  createPermission,
  grantPermissionToRole,
  assignRoleToPrincipal,
  registerOrTouchDevice,
  setDeviceTrustLevel,
  createSession,
  issueAccessToken,
  getSessionById,
} from "@distrisec/identity";
import { getDb as getAuditDb, verifyChain, schema as auditSchema } from "@distrisec/audit-log";
import { evaluateAccessRequest } from "../gateway.js";

/** The same three example rules from the project spec, used throughout. */
const TEST_POLICY: Policy = parse(
  tokenize(`
    rule "developer-db-read" {
      effect: allow
      when: role == "developer" AND resource.type == "database" AND action == "read" AND device.trust == "trusted"
    }

    rule "high-risk-deny" {
      effect: deny
      when: risk.score > 80
    }

    rule "country-change-step-up" {
      effect: step_up
      when: country != previous_country
    }
  `),
);

/** Sets up a fully real user + developer role + trusted device + session + token. */
async function setupDeveloper(email: string, country: string) {
  const db = getIdentityDb();
  const user = await createUser(db, { email, displayName: "Dev", password: "pw12345678" });
  const role = await createRole(db, "developer");
  const readPerm = await createPermission(db, { resourceType: "database", action: "read" });
  await grantPermissionToRole(db, role.id, readPerm.id);
  await assignRoleToPrincipal(db, user.id, "user", role.id);

  const device = await registerOrTouchDevice(db, {
    fingerprint: `fp-${email}`,
    ownerPrincipalId: user.id,
    ownerPrincipalKind: "user",
  });
  await setDeviceTrustLevel(db, device.id, "trusted");

  const session = await createSession(db, {
    principalId: user.id,
    principalKind: "user",
    deviceId: device.id,
    country,
  });

  const token = await issueAccessToken(db, {
    principalId: user.id,
    principalKind: "user",
    deviceId: device.id,
    sessionId: session.id,
  });

  return { db, user, device, session, token };
}

describe("evaluateAccessRequest: end-to-end through real identity + policy evaluation", () => {
  it("allows a trusted developer reading a database from their usual country", async () => {
    const { token } = await setupDeveloper("gw-allow@acme.com", "IN");

    const result = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN", // same as the session's recorded country - no change
    });

    expect(result.decision.effect).toBe("allow");
    expect(result.decision.matchedRuleIds).toEqual(["developer-db-read"]);
  });

  it("denies a request with an invalid/unknown token without leaking why", async () => {
    const result = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, "not-a-real-token", {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN",
    });

    expect(result.decision.effect).toBe("deny");
    expect(result.decision.reason).toBe("Invalid token");
    expect(result.context).toBeNull();
  });

  it("requires step-up on a country change, and actually marks the session as such", async () => {
    const { token, session, db } = await setupDeveloper("gw-stepup@acme.com", "IN");

    const result = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "198.51.100.9",
      country: "GB", // different from the session's recorded "IN"
    });

    expect(result.decision.effect).toBe("step_up");
    expect(result.decision.matchedRuleIds).toEqual(["country-change-step-up"]);

    const updatedSession = await getSessionById(db, session.id);
    expect(updatedSession?.status).toBe("step_up_required");
  });
});

describe("ordering edge case: previousCountry must reflect the country BEFORE this request", () => {
  it("a country change is only caught ONCE - the second request from the new country is not flagged again", async () => {
    const { token, db, session } = await setupDeveloper("gw-ordering@acme.com", "IN");

    const requestFromGB = {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "198.51.100.9",
      country: "GB",
    };

    const first = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, requestFromGB);
    expect(first.decision.effect).toBe("step_up");

    const afterFirst = await getSessionById(db, session.id);
    expect(afterFirst?.lastKnownCountry).toBe("GB");

    const second = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, requestFromGB);
    expect(second.decision.effect).toBe("allow");
    expect(second.decision.matchedRuleIds).toEqual(["developer-db-read"]);
  });
});

describe("audit logging", () => {
  it("every allowed request produces a matching, verifiable audit entry", async () => {
    const { token, user } = await setupDeveloper("gw-audit-allow@acme.com", "IN");

    await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN",
    });

    const auditDb = getAuditDb();
    const [entry] = await auditDb
      .select()
      .from(auditSchema.auditLogEntries)
      .where(eq(auditSchema.auditLogEntries.principalId, user.id));

    expect(entry).toBeDefined();
    expect(entry!.result).toBe("allow");
    expect(entry!.resourceType).toBe("database");
    expect(entry!.action).toBe("read");

    const verification = await verifyChain(auditDb);
    expect(verification.valid).toBe(true);
  });

  it("a request with an invalid token is STILL logged, using the unknown-principal sentinel", async () => {
    await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, "a-completely-fake-token", {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN",
    });

    const auditDb = getAuditDb();
    const [entry] = await auditDb
      .select()
      .from(auditSchema.auditLogEntries)
      .where(eq(auditSchema.auditLogEntries.resourceId, "customers-db"));

    expect(entry).toBeDefined();
    expect(entry!.result).toBe("deny");
    expect(entry!.reason).toMatch(/Invalid token/);
    expect(entry!.principalId).toBe("00000000-0000-0000-0000-000000000000");
  });

  it("end-to-end: a real gateway session's audit trail detects tampering after the fact", async () => {
    const { token } = await setupDeveloper("gw-tamper-e2e@acme.com", "IN");

    await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN",
    });
    await evaluateAccessRequest(getIdentityDb(), getAuditDb(), TEST_POLICY, token.raw, {
      resourceType: "database",
      resourceId: "customers-db",
      action: "read",
      ip: "203.0.113.5",
      country: "IN",
    });

    const auditDb = getAuditDb();
    const beforeTamper = await verifyChain(auditDb);
    expect(beforeTamper.valid).toBe(true);

    const [firstEntry] = await auditDb
      .select()
      .from(auditSchema.auditLogEntries)
      .orderBy(auditSchema.auditLogEntries.sequence)
      .limit(1);
    await auditDb.execute(
      sql`UPDATE audit_log_entries SET reason = 'covering tracks' WHERE id = ${firstEntry!.id}`,
    );

    const afterTamper = await verifyChain(auditDb);
    expect(afterTamper.valid).toBe(false);
    if (!afterTamper.valid) {
      expect(afterTamper.brokenAtSequence).toBe(firstEntry!.sequence);
    }
  });
});