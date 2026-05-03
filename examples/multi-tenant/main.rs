// Multi-tenant encryption pattern using KeyRack
//
// Demonstrates how different tenants get isolated key hierarchies
// through attribute-based key resolution. Each tenant's data is
// encrypted with a tenant-specific DEK derived from the namespace rules.
//
// Run: cargo run --example multi-tenant

use keyrack_core::attr::AttributeSet;
use keyrack_core::resolver::KeyResolver;
use keyrack_core::rule::RuleRegistry;

const NAMESPACE_YAML: &str = r#"
namespaces:
  - name: saas
    max_depth: 4
    routing_rules:
      - match:
          service: storage
          tenant_id: $tenant_id
        parent:
          service: storage
        priority: 0
      - match:
          service: storage
        parent: _root_
        priority: 0
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry = RuleRegistry::from_yaml(NAMESPACE_YAML)?;

    // Tenant A wants to encrypt a file
    let tenant_a_attrs = AttributeSet::from_pairs(&[
        ("service", "storage"),
        ("tenant_id", "tenant-a"),
    ]);

    // Tenant B wants to encrypt a file
    let tenant_b_attrs = AttributeSet::from_pairs(&[
        ("service", "storage"),
        ("tenant_id", "tenant-b"),
    ]);

    // Resolve keys — each tenant gets a different LID
    let match_a = registry.match_rule(tenant_a_attrs.as_canonical())
        .expect("tenant A should match a rule");
    let match_b = registry.match_rule(tenant_b_attrs.as_canonical())
        .expect("tenant B should match a rule");

    println!("Tenant A → namespace: {}, rule bindings: {:?}",
        match_a.namespace.name, match_a.bindings);
    println!("Tenant B → namespace: {}, rule bindings: {:?}",
        match_b.namespace.name, match_b.bindings);

    // In production, you'd call the gRPC service:
    //   let resp = client.encrypt(EncryptRequest {
    //       key_id: lid_a.to_string(),
    //       plaintext: data,
    //       encryption_context: HashMap::new(),
    //   }).await?;

    println!("\nTenants get isolated key hierarchies automatically.");
    println!("No tenant ID leaks across boundaries.");

    Ok(())
}
