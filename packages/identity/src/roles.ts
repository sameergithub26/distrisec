import { eq, and, inArray } from "drizzle-orm";
import type { Database } from "./db/client.js";
import {
  roles,
  permissions,
  rolePermissions,
  principalRoles,
} from "./db/schema.js";

export type PrincipalKind = "user" | "service_account";

export async function createRole(db: Database, name: string) {
  const [role] = await db.insert(roles).values({ name }).returning();
  return role!;
}

export async function createPermission(
  db: Database,
  input: { resourceType: string; action: string },
) {
  const [permission] = await db.insert(permissions).values(input).returning();
  return permission!;
}

export async function grantPermissionToRole(
  db: Database,
  roleId: string,
  permissionId: string,
) {
  await db
    .insert(rolePermissions)
    .values({ roleId, permissionId })
    .onConflictDoNothing();
}

export async function assignRoleToPrincipal(
  db: Database,
  principalId: string,
  principalKind: PrincipalKind,
  roleId: string,
) {
  await db
    .insert(principalRoles)
    .values({ principalId, principalKind, roleId })
    .onConflictDoNothing();
}

export async function revokeRoleFromPrincipal(
  db: Database,
  principalId: string,
  roleId: string,
) {
  await db
    .delete(principalRoles)
    .where(
      and(
        eq(principalRoles.principalId, principalId),
        eq(principalRoles.roleId, roleId),
      ),
    );
}

/** Returns the role names currently assigned to a principal. */
export async function getPrincipalRoleNames(
  db: Database,
  principalId: string,
): Promise<string[]> {
  const rows = await db
    .select({ name: roles.name })
    .from(principalRoles)
    .innerJoin(roles, eq(roles.id, principalRoles.roleId))
    .where(eq(principalRoles.principalId, principalId));

  return rows.map((r) => r.name);
}

/**
 * Resolves the full set of (resourceType, action) permissions a principal
 * currently has, by walking principal -> roles -> permissions.
 * This is the function the policy engine calls to check "can this principal
 * even theoretically take this action" before context-specific rules apply.
 */
export async function getEffectivePermissions(
  db: Database,
  principalId: string,
): Promise<Array<{ resourceType: string; action: string }>> {
  const assignedRoleIds = await db
    .select({ roleId: principalRoles.roleId })
    .from(principalRoles)
    .where(eq(principalRoles.principalId, principalId));

  if (assignedRoleIds.length === 0) return [];

  const roleIds = assignedRoleIds.map((r) => r.roleId);

  const rows = await db
    .select({
      resourceType: permissions.resourceType,
      action: permissions.action,
    })
    .from(rolePermissions)
    .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(inArray(rolePermissions.roleId, roleIds));

  // de-dupe, since multiple roles can grant the same permission
  const seen = new Set<string>();
  const result: Array<{ resourceType: string; action: string }> = [];
  for (const row of rows) {
    const key = `${row.resourceType}:${row.action}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(row);
    }
  }
  return result;
}
