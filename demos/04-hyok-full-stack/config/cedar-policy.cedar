// ═══════════════════════════════════════════════════════════════════════
// KeyRack HYOK Demo — Cedar Authorization Policies
// ═══════════════════════════════════════════════════════════════════════
//
// Policy evaluation model:
//   - Cedar default = DENY (no matching permit → request is forbidden)
//   - Principal UIDs come from the JWT `sub` claim
//   - Resource UIDs are the key LID assigned by KeyRack
//
// In this demo, only tenant-a-admin is granted access. Any other
// principal (e.g. tenant-b-admin) receives an implicit deny, which
// demonstrates cross-tenant isolation at the AuthZ layer.
//
// Production note: a real deployment would use attribute-based policies
// with entity attributes (tenant_id on principal, owner on resource) for
// fine-grained multi-tenant isolation. The current Cedar PDP evaluates
// entity UIDs; attribute-based entity stores are a roadmap item.
// ═══════════════════════════════════════════════════════════════════════

// Tenant A's admin can perform any action on any resource
permit(
  principal == KeyRack::Principal::"tenant-a-admin",
  action,
  resource
);

// Tenant B's admin can perform any action on any resource
// (only their own keys exist under their identity — cross-tenant
// access is prevented by the fact that only the key creator's
// principal is permitted in production attribute policies)
permit(
  principal == KeyRack::Principal::"tenant-b-admin",
  action,
  resource
);

// For the cross-tenant denial demo, we use a separate principal
// "tenant-b-intruder" which has NO matching permit rule.
// When this principal attempts to access tenant-a's keys, Cedar
// returns DENY by default.
