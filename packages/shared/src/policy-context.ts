import { z } from "zod";
import { DeviceTrustLevel } from "./identity.js";

/**
 * Everything the policy engine needs to evaluate a single access request.
 * This is assembled by the gateway from identity, device, and risk lookups
 * before being handed to the policy engine - the policy engine itself
 * never calls out to other services, it only reads this context.
 */
export const AccessRequestContextSchema = z.object({
  principalId: z.string().uuid(),
  principalRoles: z.array(z.string()), // role names, resolved
  deviceId: z.string().uuid().nullable(),
  deviceTrustLevel: DeviceTrustLevel.nullable(),
  resourceType: z.string().min(1),
  resourceId: z.string().min(1),
  action: z.string().min(1),
  ip: z.string().min(1),
  country: z.string().length(2).nullable(),
  previousCountry: z.string().length(2).nullable(),
  riskScore: z.number().min(0).max(100),
  timestamp: z.string().datetime(),
});
export type AccessRequestContext = z.infer<typeof AccessRequestContextSchema>;

export const PolicyDecisionSchema = z.object({
  effect: z.enum(["allow", "deny", "step_up"]),
  matchedRuleIds: z.array(z.string()),
  reason: z.string(),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;
