import { describe, it, expect } from "vitest";
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
} from "@distrisec/identity";
import { getDb as getAuditDb } from "@distrisec/audit-log";
import { EventBus } from "@distrisec/event-pipeline";
import { DetectionService, type DetectionFlag } from "@distrisec/threat-detection";
import { evaluateAccessRequest } from "../gateway.js";

const POLICY: Policy = parse(
  tokenize(`
    rule "developer-db-read" {
      effect: allow
      when: role == "developer" AND resource.type == "database" AND action == "read" AND device.trust == "trusted"
    }
    rule "country-change-step-up" {
      effect: step_up
      when: country != previous_country
    }
  `),
);

async function setupDeveloper(email: string, country: string) {
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
  return { token };
}

const req = (country: string) => ({
  resourceType: "database",
  resourceId: "customers-db",
  action: "read",
  ip: "203.0.113.5",
  country,
});

describe("gateway -> event bus -> threat detection (Phase 4 end to end)", () => {
  it("real requests from India then the UK seconds apart raise impossible_travel", async () => {
    const { token } = await setupDeveloper("pipe-travel@acme.com", "IN");
    const flags: DetectionFlag[] = [];
    const bus = new EventBus();
    new DetectionService({ onFlag: (f) => { flags.push(f); } }).attach(bus);

    await evaluateAccessRequest(getIdentityDb(), getAuditDb(), POLICY, token.raw, req("IN"), { eventBus: bus });
    expect(flags).toEqual([]);

    const second = await evaluateAccessRequest(
      getIdentityDb(), getAuditDb(), POLICY, token.raw, req("GB"), { eventBus: bus },
    );

    expect(flags.map((f) => f.detector)).toEqual(["impossible_travel"]);
    // The policy engine independently stepped this up too: two separate
    // controls (a policy rule and a detector) caught the same event.
    expect(second.decision.effect).toBe("step_up");
  });

  it("ordinary repeated requests from one country raise nothing", async () => {
    const { token } = await setupDeveloper("pipe-normal@acme.com", "IN");
    const flags: DetectionFlag[] = [];
    const bus = new EventBus();
    new DetectionService({ onFlag: (f) => { flags.push(f); } }).attach(bus);

    for (let i = 0; i < 3; i++) {
      await evaluateAccessRequest(getIdentityDb(), getAuditDb(), POLICY, token.raw, req("IN"), { eventBus: bus });
    }
    expect(flags).toEqual([]);
  });

  it("a broken subscriber can never change an access decision", async () => {
    const { token } = await setupDeveloper("pipe-broken@acme.com", "IN");
    const bus = new EventBus();
    bus.subscribe(() => {
      throw new Error("detector crashed");
    });

    const result = await evaluateAccessRequest(
      getIdentityDb(), getAuditDb(), POLICY, token.raw, req("IN"), { eventBus: bus },
    );
    expect(result.decision.effect).toBe("allow");
  });

  it("works exactly as before when no bus is supplied", async () => {
    const { token } = await setupDeveloper("pipe-nobus@acme.com", "IN");
    const result = await evaluateAccessRequest(getIdentityDb(), getAuditDb(), POLICY, token.raw, req("IN"));
    expect(result.decision.effect).toBe("allow");
  });
});