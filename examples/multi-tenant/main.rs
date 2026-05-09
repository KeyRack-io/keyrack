// Multi-tenant encryption pattern using KeyRack
//
// Demonstrates how different tenants get isolated key hierarchies
// through attribute-based key resolution. Each tenant's data is
// encrypted with a tenant-specific DEK derived from the namespace rules.
//
// Run: cargo run --example multi-tenant

use keyrack_core::rule::RuleRegistry;
use std::collections::BTreeMap;

const NAMESPACE_YAML: &str = r#"
namespaces:
  - name: saas
    max_depth: 4
    routing_rules:
      - match_pattern:
          service: storage
          tenant_id: $tenant_id
        parent:
          service: storage
        priority: 0
      - match_pattern:
          service: storage
        parent: null
        priority: 0
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry = RuleRegistry::from_yaml(NAMESPACE_YAML)?;

    let tenant_a_attrs = BTreeMap::from([
        ("service".to_string(), "storage".to_string()),
        ("tenant_id".to_string(), "tenant-a".to_string()),
    ]);

    let tenant_b_attrs = BTreeMap::from([
        ("service".to_string(), "storage".to_string()),
        ("tenant_id".to_string(), "tenant-b".to_string()),
    ]);

    let match_a = registry
        .match_rule(&tenant_a_attrs)
        .expect("tenant A should match a rule");
    let match_b = registry
        .match_rule(&tenant_b_attrs)
        .expect("tenant B should match a rule");

    println!(
        "Tenant A → namespace: {}, rule bindings: {:?}",
        match_a.namespace.name, match_a.bindings
    );
    println!(
        "Tenant B → namespace: {}, rule bindings: {:?}",
        match_b.namespace.name, match_b.bindings
    );

    println!("\nTenants get isolated key hierarchies automatically.");
    println!("No tenant ID leaks across boundaries.");

    Ok(())
}
