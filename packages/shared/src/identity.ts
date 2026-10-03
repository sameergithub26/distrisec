import { z } from "zod";

/**
 * A principal is anything that can be granted access: a human user,
 * a service account, or (indirectly, via its own identity) a device.
 */
export const PrincipalKind = z.enum(["user", "service_account"]);
export type PrincipalKind = z.infer<typeof PrincipalKind>;

export const UserSchema = z.object({
  id: z.string().uuid(),
  kind: z.literal("user"),
  email: z.string().email(),
  displayName: z.string().min(1),
  roleIds: z.array(z.string().uuid()),
  createdAt: z.string().datetime(),
  disabled: z.boolean().default(false),
});
export type User = z.infer<typeof UserSchema>;

export const ServiceAccountSchema = z.object({
  id: z.string().uuid(),
  kind: z.literal("service_account"),
  name: z.string().min(1),
  ownerUserId: z.string().uuid(),
  roleIds: z.array(z.string().uuid()),
  createdAt: z.string().datetime(),
  disabled: z.boolean().default(false),
});
export type ServiceAccount = z.infer<typeof ServiceAccountSchema>;

export const PrincipalSchema = z.discriminatedUnion("kind", [
  UserSchema,
  ServiceAccountSchema,
]);
export type Principal = z.infer<typeof PrincipalSchema>;

/**
 * A device is a distinct trust boundary from the principal using it.
 * The same user on a managed laptop vs. an unknown phone should
 * produce different access decisions.
 */
export const DeviceTrustLevel = z.enum(["trusted", "unmanaged", "unknown"]);
export type DeviceTrustLevel = z.infer<typeof DeviceTrustLevel>;

export const DeviceIdentitySchema = z.object({
  id: z.string().uuid(),
  fingerprint: z.string().min(1), // derived from TLS cert / hardware attestation / etc.
  ownerPrincipalId: z.string().uuid(),
  trustLevel: DeviceTrustLevel,
  firstSeenAt: z.string().datetime(),
  lastSeenAt: z.string().datetime(),
});
export type DeviceIdentity = z.infer<typeof DeviceIdentitySchema>;

/** Roles bundle permissions. Permissions are resource:action pairs. */
export const PermissionSchema = z.object({
  id: z.string().uuid(),
  resourceType: z.string().min(1), // e.g. "database", "api", "cloud_resource"
  action: z.string().min(1), // e.g. "read", "write", "admin"
});
export type Permission = z.infer<typeof PermissionSchema>;

export const RoleSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1), // e.g. "developer", "admin", "auditor"
  permissionIds: z.array(z.string().uuid()),
});
export type Role = z.infer<typeof RoleSchema>;

/**
 * Opaque, short-lived access token. The token VALUE is never stored —
 * only a hash of it — so a DB leak doesn't leak usable tokens.
 */
export const AccessTokenSchema = z.object({
  id: z.string().uuid(),
  tokenHash: z.string().min(1),
  principalId: z.string().uuid(),
  deviceId: z.string().uuid().nullable(),
  sessionId: z.string().uuid(),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revokedAt: z.string().datetime().nullable(),
  rotatedFromTokenId: z.string().uuid().nullable(),
});
export type AccessToken = z.infer<typeof AccessTokenSchema>;

export const SessionStatus = z.enum([
  "active",
  "step_up_required",
  "revoked",
  "expired",
]);
export type SessionStatus = z.infer<typeof SessionStatus>;

export const SessionSchema = z.object({
  id: z.string().uuid(),
  principalId: z.string().uuid(),
  deviceId: z.string().uuid().nullable(),
  status: SessionStatus,
  createdAt: z.string().datetime(),
  lastActivityAt: z.string().datetime(),
  lastKnownCountry: z.string().length(2).nullable(), // ISO 3166-1 alpha-2
  currentRiskScore: z.number().min(0).max(100).default(0),
});
export type Session = z.infer<typeof SessionSchema>;
