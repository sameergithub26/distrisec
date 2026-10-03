import { z } from "zod";

export const EventResult = z.enum(["allow", "deny", "step_up_required", "error"]);
export type EventResult = z.infer<typeof EventResult>;

/**
 * Canonical shape for every security-relevant action in the system.
 * This is what flows through the event pipeline, feeds the detectors,
 * and gets written to the audit log.
 */
export const SecurityEventSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime(),
  principalId: z.string().uuid(),
  sessionId: z.string().uuid().nullable(),
  deviceId: z.string().uuid().nullable(),
  action: z.string().min(1), // e.g. "read", "write", "login", "role_change"
  resourceType: z.string().min(1), // e.g. "database", "api", "cloud_resource"
  resourceId: z.string().min(1),
  ip: z.string().min(1),
  country: z.string().length(2).nullable(),
  result: EventResult,
  riskScoreAtDecision: z.number().min(0).max(100).nullable(),
  metadata: z.record(z.unknown()).default({}),
});
export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

/** Factory for building events with sane defaults, used heavily in tests and the simulator. */
export function createSecurityEvent(
  partial: Omit<SecurityEvent, "id" | "timestamp" | "metadata"> &
    Partial<Pick<SecurityEvent, "metadata">>,
): SecurityEvent {
  return SecurityEventSchema.parse({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    metadata: {},
    ...partial,
  });
}
