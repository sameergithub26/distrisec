import { hash, verify } from "@node-rs/argon2";
import { randomBytes, createHash } from "node:crypto";

/** Argon2id with reasonable interactive-login parameters (OWASP 2024 guidance ballpark). */
const ARGON2_OPTIONS = {
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
};

export async function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, ARGON2_OPTIONS);
}

export async function verifyPassword(plaintext: string, storedHash: string): Promise<boolean> {
  return verify(storedHash, plaintext, ARGON2_OPTIONS);
}

/**
 * Generates an opaque bearer token. The RAW value is returned to the
 * caller once and never stored; only its SHA-256 hash is persisted,
 * so a DB compromise alone can't produce usable tokens.
 */
export function generateOpaqueToken(): { raw: string; hash: string } {
  const raw = randomBytes(32).toString("base64url");
  return { raw, hash: hashToken(raw) };
}

export function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}
