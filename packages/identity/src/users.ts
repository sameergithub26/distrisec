import { eq } from "drizzle-orm";
import type { Database } from "./db/client.js";
import { users } from "./db/schema.js";
import { hashPassword, verifyPassword } from "./crypto.js";

export class UserAlreadyExistsError extends Error {
  constructor(email: string) {
    super(`A user with email "${email}" already exists`);
    this.name = "UserAlreadyExistsError";
  }
}

export async function createUser(
  db: Database,
  input: { email: string; displayName: string; password: string },
) {
  const existing = await db.query.users.findFirst({
    where: eq(users.email, input.email.toLowerCase()),
  });
  if (existing) {
    throw new UserAlreadyExistsError(input.email);
  }

  const passwordHash = await hashPassword(input.password);
  const [user] = await db
    .insert(users)
    .values({
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash,
    })
    .returning();

  return user!;
}

export async function getUserById(db: Database, id: string) {
  return db.query.users.findFirst({ where: eq(users.id, id) });
}

export async function getUserByEmail(db: Database, email: string) {
  return db.query.users.findFirst({ where: eq(users.email, email.toLowerCase()) });
}

/**
 * Verifies a password against the stored hash. Deliberately constant-shape:
 * always hashes against a dummy value when the user doesn't exist, so the
 * response timing doesn't reveal whether an email is registered.
 */
export async function authenticateWithPassword(
  db: Database,
  email: string,
  password: string,
): Promise<{ ok: true; userId: string } | { ok: false; reason: "not_found" | "disabled" | "bad_password" }> {
  const user = await getUserByEmail(db, email);

  if (!user) {
    await verifyPassword(password, DUMMY_HASH).catch(() => undefined);
    return { ok: false, reason: "not_found" };
  }
  if (user.disabled) {
    return { ok: false, reason: "disabled" };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    return { ok: false, reason: "bad_password" };
  }

  return { ok: true, userId: user.id };
}

// Precomputed argon2id hash of a random value, used only for timing-attack mitigation above.
const DUMMY_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Y8OdE7cQnG3F2kqj6N2mUoVvYV9N9f1J4mOqkqF9xyM";
