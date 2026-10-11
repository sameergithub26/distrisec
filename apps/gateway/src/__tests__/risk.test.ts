import { describe, it, expect } from "vitest";
import { eq } from "drizzle-orm";
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
import { EventBus } from "@distrisec/event-pipeline";
import { DetectionService, type DetectionFlag } from "@distrisec/threat-detection";
import { RiskEngine } from "@distrisec/risk-engine";
import { evaluateAccessRequest } from "../gateway.js";

// A three-tier policy: the risk score now drives real enforcement.
const POLICY: Policy = parse(
  tokenize(`
    rule "developer-db-read" {
      effect: allow
      when: role == "developer" AND resource.type == "database" AND action == "read" AND device.trust == "trusted"
    }
    rule "critical-risk-deny" {
      effect: deny
      when: risk.score >= 75
    }
    rule "elevated-risk-step-up" {
      effect: step_up
      when: risk.score >= 40
    }
    rule "country-change-step-up" {
      effect: step_up
      when: country != previous_country
    }
  `),
);

async function setupDeveloper(email: string, country: string, trust: "trusted" | "unmanaged" = "trusted") {
  const db = getIdentityDb();
  const user = await createUser(db, { email, displayName: "Dev", password: "pw12345678" });
  const role = await createRole(db, "developer");
  const perm = await createPermission(db, { resourceType: "database", action: "read" });
  await grantPermissionToRole(db, role.id, perm.id);
  await assignRoleToPrincipal(db, user.id, "user", role.id);
  const device = await registerOrTouchDevice(db, {
    fingerprint: `fp-${email}`,
    ownerPrincipalId: user.id,
    ownerPrincipalKind: "user",
  });
  await setDeviceTrustLevel(db, device.id, trust);
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
  return { user, session, token };
}

const req = (country: string) => ({
  resourceType: "database",
  resourceId: "customers-db",
  action: "read",
  ip: "203.0.113.5",
  country,
});

/** Full pipeline wiring: bus -> detectors -> risk engine, all in one place. */
function buildPipeline() {
  const risk = new RiskEngine();
  const bus = new EventBus();
  const flags: DetectionFlag[] = [];
  new DetectionService({
    onFlag: (f) => {
      flags.push(f);
      risk.recordFlag(f);
    },
  }).attach(bus);
  return { risk, bus, flags };
}

const run = (token: string, country: string, p: ReturnType<typeof buildPipeline>) =>
  evaluateAccessRequest(getIdentityDb(), getAuditDb(), POLICY, token, req(country), {
    eventBus: p.bus,
    riskScorer: p.risk,
  });

describe("risk engine in the gateway: bad behaviour -> detection -> risk score -> denied", () => {
  it("a clean user on a trusted device has zero risk and is allowed", async () => {
    const p = buildPipeline();
    const { token } = await setupDeveloper("risk-clean@acme.com", "IN");
    const result = await run(token.raw, "IN", p);
    expect(result.decision.effect).toBe("allow");
    expect(result.risk?.score).toBe(0);
    expect(result.risk?.band).toBe("low");
  });

  it("impossible travel is detected, scored critical, and the NEXT request is denied", async () => {
    const p = buildPipeline();
    const { token } = await setupDeveloper("risk-travel@acme.com", "IN");

    const first = await run(token.raw, "IN", p);
    expect(first.decision.effect).toBe("allow");

    // India -> UK seconds later. The country-change policy rule steps this
    // request up, and the detector independently raises a critical flag
    // (published after this decision, so it scores the NEXT request).
    const second = await run(token.raw, "GB", p);
    expect(second.decision.effect).toBe("step_up");
    expect(p.flags.map((f) => f.detector)).toEqual(["impossible_travel"]);

    // Same country as the last request, so no country-change rule fires -
    // the ONLY thing that can deny this request is the accumulated risk.
    const third = await run(token.raw, "GB", p);
    expect(third.risk?.band).toBe("critical");
    expect(third.decision.effect).toBe("deny");
    expect(third.decision.matchedRuleIds).toEqual(["critical-risk-deny"]);
  });

  it("a lower-severity signal steps the user up instead of denying", async () => {
    const p = buildPipeline();
    const { user, token } = await setupDeveloper("risk-mid@acme.com", "IN");
    p.risk.recordFlag({
      detector: "token_anomaly",
      severity: "high", // contributes 50: above the step-up bar (40), below deny (75)
      principalId: user.id,
      message: "synthetic high-severity flag",
      evidenceEventIds: [],
      details: {},
    });

    const result = await run(token.raw, "IN", p);
    expect(result.decision.effect).toBe("step_up");
    expect(result.decision.matchedRuleIds).toEqual(["elevated-risk-step-up"]);
  });

  it("one user's flags never affect another user's decisions", async () => {
    const p = buildPipeline();
    const bad = await setupDeveloper("risk-bad@acme.com", "IN");
    p.risk.recordFlag({
      detector: "impossible_travel",
      severity: "critical",
      principalId: bad.user.id,
      message: "synthetic",
      evidenceEventIds: [],
      details: {},
    });

    const db = getIdentityDb();
    const other = await createUser(db, { email: "risk-other@acme.com", displayName: "Other", password: "pw12345678" });
    const dev = await db.query.roles.findFirst();
    await assignRoleToPrincipal(db, other.id, "user", dev!.id);
    const device = await registerOrTouchDevice(db, {
      fingerprint: "fp-other",
      ownerPrincipalId: other.id,
      ownerPrincipalKind: "user",
    });
    await setDeviceTrustLevel(db, device.id, "trusted");
    const session = await createSession(db, {
      principalId: other.id,
      principalKind: "user",
      deviceId: device.id,
      country: "IN",
    });
    const token = await issueAccessToken(db, {
      principalId: other.id,
      principalKind: "user",
      deviceId: device.id,
      sessionId: session.id,
    });

    const result = await run(token.raw, "IN", p);
    expect(result.decision.effect).toBe("allow");
    expect(result.risk?.score).toBe(0);
  });

  it("a less-trusted device raises the score but alone is not enough to block", async () => {
    const p = buildPipeline();
    const { token } = await setupDeveloper("risk-device@acme.com", "IN", "unmanaged");
    const result = await run(token.raw, "IN", p);
    expect(result.risk?.score).toBe(15);
    expect(result.risk?.components.map((c) => c.name)).toEqual(["device"]);
    // (The allow rule itself needs a TRUSTED device, so this is denied by
    // default-deny - the point is the score is explained and is not 75+.)
    expect(result.decision.matchedRuleIds).not.toContain("critical-risk-deny");
  });

  it("persists the score on the session so other tools can see it", async () => {
    const p = buildPipeline();
    const { user, session, token } = await setupDeveloper("risk-persist@acme.com", "IN");
    p.risk.recordFlag({
      detector: "token_anomaly",
      severity: "high",
      principalId: user.id,
      message: "synthetic",
      evidenceEventIds: [],
      details: {},
    });
    await run(token.raw, "IN", p);
    const stored = await getSessionById(getIdentityDb(), session.id);
    expect(stored!.currentRiskScore).toBeGreaterThanOrEqual(50);
  });

  it("records WHY in the audit trail: the score, band, and contributing components", async () => {
    const p = buildPipeline();
    const { user, token } = await setupDeveloper("risk-audit@acme.com", "IN");
    p.risk.recordFlag({
      detector: "impossible_travel",
      severity: "critical",
      principalId: user.id,
      message: "synthetic",
      evidenceEventIds: [],
      details: {},
    });
    await run(token.raw, "IN", p);

    const auditDb = getAuditDb();
    const [entry] = await auditDb
      .select()
      .from(auditSchema.auditLogEntries)
      .where(eq(auditSchema.auditLogEntries.principalId, user.id));

    const meta = entry!.metadata as { risk: { score: number; band: string; components: { name: string }[] } };
    expect(meta.risk.band).toBe("critical");
    expect(meta.risk.components.map((c) => c.name)).toContain("recent_flag:impossible_travel");
    // Floats and nested arrays went through jsonb - the chain must still verify.
    expect((await verifyChain(auditDb)).valid).toBe(true);
  });

  it("still works exactly as before when no risk scorer is supplied", async () => {
    const { token } = await setupDeveloper("risk-none@acme.com", "IN");
    const result = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), POLICY, token.raw, req("IN"));
    expect(result.decision.effect).toBe("allow");
    expect(result.risk).toBeNull();
  });
});