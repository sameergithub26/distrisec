import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema.js";

const { Pool } = pg;

let pool: InstanceType<typeof Pool> | undefined;

/** Lazily-created singleton pool + drizzle instance, so importing this
 * module doesn't attempt a DB connection until something is actually queried. */
export function getDb() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL ?? "postgres://localhost:5432/distrisec",
    });
  }
  return drizzle(pool, { schema });
}

export type Database = ReturnType<typeof getDb>;

export async function closeDb() {
  await pool?.end();
  pool = undefined;
}
