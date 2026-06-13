// ═══════════════════════════════════════════════════════════════════════
// Demo 10 — mTLS identity → authorization
// ═══════════════════════════════════════════════════════════════════════
//
// Cedar is deny-by-default: a principal with no matching `permit` is forbidden.
//
// The principal id is taken from the client TLS certificate (its CN, or a
// SPIFFE SAN if present). Here only `alice` is permitted; `bob` presents an
// equally valid certificate but has no matching permit, so the PDP denies the
// request. This is what proves the certificate identity is actually carried
// into the authorization decision.
// ═══════════════════════════════════════════════════════════════════════

permit(
  principal == KeyRack::Principal::"alice",
  action,
  resource
);
