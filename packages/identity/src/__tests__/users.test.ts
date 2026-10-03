import { describe, it, expect } from "vitest";
import { getDb } from "../db/client.js";
import { createUser, authenticateWithPassword, UserAlreadyExistsError } from "../users.js";

describe("createUser", () => {
  it("creates a user with a hashed password, never the plaintext", async () => {
    const db = getDb();
    const user = await createUser(db, {
      email: "alice@acme.com",
      displayName: "Alice",
      password: "correct-horse-battery-staple",
    });

    expect(user.email).toBe("alice@acme.com");
    // The stored value must never equal the plaintext we sent in -
    // if this ever passes, something is storing passwords in the clear.
    expect(user.passwordHash).not.toBe("correct-horse-battery-staple");
    expect(user.passwordHash.startsWith("$argon2id$")).toBe(true);
  });

  it("lowercases email so the same address can't register twice with different casing", async () => {
    const db = getDb();
    const user = await createUser(db, {
      email: "Alice@ACME.com",
      displayName: "Alice",
      password: "whatever12345",
    });
    expect(user.email).toBe("alice@acme.com");
  });

  it("rejects a second signup with an email that already exists", async () => {
    const db = getDb();
    await createUser(db, { email: "bob@acme.com", displayName: "Bob", password: "pw123456789" });

    await expect(
      createUser(db, { email: "bob@acme.com", displayName: "Bob Again", password: "different12345" }),
    ).rejects.toThrow(UserAlreadyExistsError);
  });
});

describe("authenticateWithPassword", () => {
  it("succeeds with the correct password", async () => {
    const db = getDb();
    await createUser(db, { email: "carol@acme.com", displayName: "Carol", password: "s3cur3-passw0rd" });

    const result = await authenticateWithPassword(db, "carol@acme.com", "s3cur3-passw0rd");
    expect(result.ok).toBe(true);
  });

  it("fails with the wrong password, with reason bad_password", async () => {
    const db = getDb();
    await createUser(db, { email: "dave@acme.com", displayName: "Dave", password: "the-real-password" });

    const result = await authenticateWithPassword(db, "dave@acme.com", "a-guess");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_password");
  });

  it("fails for an email that was never registered, with reason not_found", async () => {
    const db = getDb();
    const result = await authenticateWithPassword(db, "nobody@acme.com", "anything12345");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_found");
  });
});
