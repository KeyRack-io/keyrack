# Cedar Starter Schema for KeyRack

This document provides a ready-to-use Cedar schema that operators can
copy into their Cedar PDP deployment. It defines the entity types,
actions, and context shapes that KeyRack's authorization requests use.

For background on Cedar, see [cedarpolicy.com](https://www.cedarpolicy.com/).

---

## Schema

```cedarschema
namespace KeyRack {

    // ── Entity types ──────────────────────────────────────

    entity User in [Group] = {
        "email"?: String,
        "department"?: String,
    };

    entity Service in [Group] = {
        "service_name"?: String,
    };

    entity Group;

    entity Key = {
        "namespace": String,
        "key_spec": String,
        "key_usage": String,
        "state": String,
        "tags"?: Record,
    };

    entity Alias = {
        "target_key": Key,
    };

    entity HsmConnection = {
        "provider_type": String,
        "namespace": String,
    };

    entity Namespace = {
        "name": String,
    };

    // ── Actions ───────────────────────────────────────────

    // Key lifecycle
    action CreateKey appliesTo {
        principal: [User, Service],
        resource: [Namespace],
        context: ContextShape,
    };

    action DescribeKey appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action EnableKey appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action DisableKey appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action ScheduleKeyDeletion appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action CancelKeyDeletion appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    // Cryptographic operations
    action Encrypt appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action Decrypt appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action Sign appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action Verify appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action GenerateDataKey appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action ReEncrypt appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action GenerateRandom appliesTo {
        principal: [User, Service],
        resource: [Namespace],
        context: ContextShape,
    };

    // Key rotation
    action RotateKey appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action EnableKeyRotation appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action DisableKeyRotation appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    // Aliases
    action CreateAlias appliesTo {
        principal: [User, Service],
        resource: [Namespace],
        context: ContextShape,
    };

    action DeleteAlias appliesTo {
        principal: [User, Service],
        resource: [Alias],
        context: ContextShape,
    };

    // Tags
    action TagResource appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    action UntagResource appliesTo {
        principal: [User, Service],
        resource: [Key],
        context: ContextShape,
    };

    // Listing
    action ListKeys appliesTo {
        principal: [User, Service],
        resource: [Namespace],
        context: ContextShape,
    };

    action ListAliases appliesTo {
        principal: [User, Service],
        resource: [Namespace],
        context: ContextShape,
    };

    // HSM connections (admin)
    action CreateHsmConnection appliesTo {
        principal: [User],
        resource: [Namespace],
        context: ContextShape,
    };

    action DeleteHsmConnection appliesTo {
        principal: [User],
        resource: [HsmConnection],
        context: ContextShape,
    };

    // ── Context shape ─────────────────────────────────────

    type ContextShape = {
        "source_ip"?: String,
        "user_agent"?: String,
        "request_time"?: String,
        "mfa_authenticated"?: Bool,
    };
}
```

---

## Example policies

### Allow a service to encrypt and decrypt with any key in a namespace

```cedar
permit (
    principal == KeyRack::Service::"billing-service",
    action in [KeyRack::Action::"Encrypt", KeyRack::Action::"Decrypt"],
    resource in KeyRack::Namespace::"production"
);
```

### Allow admins full access

```cedar
permit (
    principal in KeyRack::Group::"admins",
    action,
    resource
);
```

### Deny deletion of keys in production unless MFA is present

```cedar
forbid (
    principal,
    action == KeyRack::Action::"ScheduleKeyDeletion",
    resource in KeyRack::Namespace::"production"
) unless {
    context.mfa_authenticated == true
};
```

### Allow read-only access for auditors

```cedar
permit (
    principal in KeyRack::Group::"auditors",
    action in [
        KeyRack::Action::"DescribeKey",
        KeyRack::Action::"ListKeys",
        KeyRack::Action::"ListAliases"
    ],
    resource
);
```

---

## Using this schema

1. Copy the schema block above into your Cedar PDP's schema file.
2. Configure KeyRack to point at your Cedar PDP via `--pdp-url` or
   `KEYRACK_PDP_URL`.
3. Write policies using the entity types and actions defined above.
4. Test policies with `cedar eval` or the Cedar playground before
   deploying.

KeyRack's authorization request shape is documented in
[`SPEC.md`](./SPEC.md) and [`PDP_WIRE_FORMAT_REQS.md`](../PDP_WIRE_FORMAT_REQS.md).
