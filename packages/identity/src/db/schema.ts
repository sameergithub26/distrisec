import {
  pgTable,
  uuid,
  text,
  timestamp,
  boolean,
  real,
  primaryKey,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  displayName: text("display_name").notNull(),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  disabled: boolean("disabled").notNull().default(false),
}, (t) => ({
  emailIdx: uniqueIndex("users_email_idx").on(t.email),
}));

export const serviceAccounts = pgTable("service_accounts", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  ownerUserId: uuid("owner_user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  disabled: boolean("disabled").notNull().default(false),
});

/**
 * Devices are owned by a "principal" which can be either a user or a
 * service account. We store the principal id loosely (not a hard FK to
 * either table) and a kind discriminator, since Postgres can't FK into
 * a union of two tables cleanly without extra machinery we don't need yet.
 */
export const devices = pgTable("devices", {
  id: uuid("id").primaryKey().defaultRandom(),
  fingerprint: text("fingerprint").notNull(),
  ownerPrincipalId: uuid("owner_principal_id").notNull(),
  ownerPrincipalKind: text("owner_principal_kind", { enum: ["user", "service_account"] }).notNull(),
  trustLevel: text("trust_level", { enum: ["trusted", "unmanaged", "unknown"] }).notNull().default("unknown"),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  fingerprintIdx: uniqueIndex("devices_fingerprint_idx").on(t.fingerprint),
}));

export const permissions = pgTable("permissions", {
  id: uuid("id").primaryKey().defaultRandom(),
  resourceType: text("resource_type").notNull(),
  action: text("action").notNull(),
}, (t) => ({
  resourceActionIdx: uniqueIndex("permissions_resource_action_idx").on(t.resourceType, t.action),
}));

export const roles = pgTable("roles", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
}, (t) => ({
  nameIdx: uniqueIndex("roles_name_idx").on(t.name),
}));

export const rolePermissions = pgTable("role_permissions", {
  roleId: uuid("role_id").notNull().references(() => roles.id, { onDelete: "cascade" }),
  permissionId: uuid("permission_id").notNull().references(() => permissions.id, { onDelete: "cascade" }),
}, (t) => ({
  pk: primaryKey({ columns: [t.roleId, t.permissionId] }),
}));

/** Role assignment, loosely FK'd to a principal the same way devices are. */
export const principalRoles = pgTable("principal_roles", {
  principalId: uuid("principal_id").notNull(),
  principalKind: text("principal_kind", { enum: ["user", "service_account"] }).notNull(),
  roleId: uuid("role_id").notNull().references(() => roles.id, { onDelete: "cascade" }),
}, (t) => ({
  pk: primaryKey({ columns: [t.principalId, t.roleId] }),
}));

export const sessions = pgTable("sessions", {
  id: uuid("id").primaryKey().defaultRandom(),
  principalId: uuid("principal_id").notNull(),
  principalKind: text("principal_kind", { enum: ["user", "service_account"] }).notNull(),
  deviceId: uuid("device_id").references(() => devices.id, { onDelete: "set null" }),
  status: text("status", { enum: ["active", "step_up_required", "revoked", "expired"] }).notNull().default("active"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastActivityAt: timestamp("last_activity_at", { withTimezone: true }).notNull().defaultNow(),
  lastKnownCountry: text("last_known_country"),
  currentRiskScore: real("current_risk_score").notNull().default(0),
});

/**
 * Only the token HASH is ever stored. The raw token is returned to the
 * caller exactly once, at issuance, and never persisted or logged.
 */
export const accessTokens = pgTable("access_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  tokenHash: text("token_hash").notNull(),
  principalId: uuid("principal_id").notNull(),
  principalKind: text("principal_kind", { enum: ["user", "service_account"] }).notNull(),
  deviceId: uuid("device_id").references(() => devices.id, { onDelete: "set null" }),
  sessionId: uuid("session_id").notNull().references(() => sessions.id, { onDelete: "cascade" }),
  issuedAt: timestamp("issued_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  rotatedFromTokenId: uuid("rotated_from_token_id"),
}, (t) => ({
  tokenHashIdx: uniqueIndex("access_tokens_token_hash_idx").on(t.tokenHash),
}));

export const usersRelations = relations(users, ({ many }) => ({
  serviceAccounts: many(serviceAccounts),
}));

export const rolesRelations = relations(roles, ({ many }) => ({
  rolePermissions: many(rolePermissions),
}));
