// E2E test Cedar policy: permit all actions for the principals used by
// keyrack-service in insecure auth mode.

// The anonymous principal (default when authn is insecure / not wired yet)
permit (
    principal == KeyRack::Principal::"keyrack:anonymous",
    action,
    resource
);

// The system principal (used for list/system-level operations)
permit (
    principal == KeyRack::Principal::"keyrack:system",
    action,
    resource
);
