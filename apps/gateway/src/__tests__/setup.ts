import "dotenv/config";
import { beforeEach, afterAll } from "vitest";
import { sql } from "drizzle-orm";
import { getDb as getIdentityDb, closeDb as closeIdentityDb } from "@distrisec/identity";
import { getDb as getAuditDb, closeDb as closeAuditDb } from "@distrisec/audit-log";

beforeEach(async () => {
  const identityDb = getIdentityDb();
  await identityDb.execute(sql`
    TRUNCATE TABLE
      access_tokens,
      principal_roles,
      role_permissions,
      sessions,
      devices,
      permissions,
      roles,
      service_accounts,
      users
    CASCADE
  `);

  // Separate table, separate Drizzle client/schema, but the SAME physical
  // Postgres database (same DATABASE_URL) - so truncating it here via
  // either client works identically; we use the audit-log package's own
  // client for clarity about which package owns this table.
  const auditDb = getAuditDb();
  await auditDb.execute(sql`TRUNCATE TABLE audit_log_entries`);
});

afterAll(async () => {
  await closeIdentityDb();
  await closeAuditDb();
});