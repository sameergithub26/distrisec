import { describe, it, expect } from "vitest";
import { getDb } from "../db/client.js";
import { createUser } from "../users.js";
import {
  createRole,
  createPermission,
  grantPermissionToRole,
  assignRoleToPrincipal,
  revokeRoleFromPrincipal,
  getEffectivePermissions,
  getPrincipalRoleNames,
} from "../roles.js";

describe("effective permission resolution", () => {
  it("a principal with no roles has no permissions", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "noone@acme.com", displayName: "No One", password: "pw12345678" });

    const perms = await getEffectivePermissions(db, user.id);
    expect(perms).toEqual([]);
  });

  it("resolves permissions by walking principal -> role -> permission", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "dev@acme.com", displayName: "Dev", password: "pw12345678" });
    const role = await createRole(db, "developer");
    const readPerm = await createPermission(db, { resourceType: "database", action: "read" });

    await grantPermissionToRole(db, role.id, readPerm.id);
    await assignRoleToPrincipal(db, user.id, "user", role.id);

    const perms = await getEffectivePermissions(db, user.id);
    expect(perms).toEqual([{ resourceType: "database", action: "read" }]);
  });

  it("de-duplicates a permission granted via two different roles", async () => {
    // This matters because without de-duping, downstream code that counts
    // permissions or iterates them would see the same (resourceType, action)
    // pair twice just because of how roles happen to be structured - a
    // purely internal data-modeling detail that should never leak out.
    const db = getDb();
    const user = await createUser(db, { email: "multi@acme.com", displayName: "Multi", password: "pw12345678" });

    const roleA = await createRole(db, "role-a");
    const roleB = await createRole(db, "role-b");
    const sharedPerm = await createPermission(db, { resourceType: "api", action: "invoke" });

    await grantPermissionToRole(db, roleA.id, sharedPerm.id);
    await grantPermissionToRole(db, roleB.id, sharedPerm.id);
    await assignRoleToPrincipal(db, user.id, "user", roleA.id);
    await assignRoleToPrincipal(db, user.id, "user", roleB.id);

    const perms = await getEffectivePermissions(db, user.id);
    expect(perms).toHaveLength(1);
  });

  it("revoking a role removes the permissions it granted", async () => {
    const db = getDb();
    const user = await createUser(db, { email: "revoke@acme.com", displayName: "Revoke Me", password: "pw12345678" });
    const role = await createRole(db, "temp-admin");
    const adminPerm = await createPermission(db, { resourceType: "database", action: "admin" });

    await grantPermissionToRole(db, role.id, adminPerm.id);
    await assignRoleToPrincipal(db, user.id, "user", role.id);
    expect(await getEffectivePermissions(db, user.id)).toHaveLength(1);

    await revokeRoleFromPrincipal(db, user.id, role.id);
    expect(await getEffectivePermissions(db, user.id)).toEqual([]);
    expect(await getPrincipalRoleNames(db, user.id)).toEqual([]);
  });
});
