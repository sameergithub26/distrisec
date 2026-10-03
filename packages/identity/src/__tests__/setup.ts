import "dotenv/config";
import { beforeEach, afterAll } from "vitest";
import { sql } from "drizzle-orm";
import { getDb, closeDb } from "../db/client.js";

/**
 * Truncate every table before each test. We use TRUNCATE ... CASCADE
 * rather than DELETE because it's much faster (no row-by-row logging)
 * and resets identity/serial sequences - not that we use serials here
 * (everything is a UUID), but it's the right default habit.
 *
 * Why before EVERY test rather than once per file: tests must not be
 * able to see data left over by a previous test, or you get flaky,
 * order-dependent tests - one of the most common causes of "works on
 * my machine, fails in CI" bugs.
 */
beforeEach(async () => {
  const db = getDb();
  await db.execute(sql`
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
});

afterAll(async () => {
  await closeDb();
});
