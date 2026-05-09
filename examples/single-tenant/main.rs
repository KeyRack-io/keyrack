// Single-tenant encryption pattern using KeyRack
//
// Shows that KeyRack works without a tenant attribute.
// A single organization uses KeyRack for key management with
// service-level isolation (different keys per service/purpose).
//
// Run: cargo run --example single-tenant

use keyrack_core::rule::RuleRegistry;
use std::collections::BTreeMap;

const NAMESPACE_YAML: &str = r#"
namespaces:
  - name: enterprise
    max_depth: 3
    routing_rules:
      - match_pattern:
          service: $service
          purpose: $purpose
        parent:
          service: $service
        priority: 0
      - match_pattern:
          service: $service
        parent: null
        priority: 0
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry = RuleRegistry::from_yaml(NAMESPACE_YAML)?;

    let services = [
        ("database", "column-encryption"),
        ("database", "backup-encryption"),
        ("messaging", "payload-encryption"),
        ("storage", "object-encryption"),
    ];

    for (service, purpose) in &services {
        let attrs = BTreeMap::from([
            ("service".to_string(), service.to_string()),
            ("purpose".to_string(), purpose.to_string()),
        ]);

        let matched = registry
            .match_rule(&attrs)
            .expect("should match a rule");

        println!(
            "service={service}, purpose={purpose} → namespace: {}, bindings: {:?}",
            matched.namespace.name, matched.bindings
        );
    }

    println!("\nNo tenant attribute needed. Keys are isolated by service/purpose.");

    Ok(())
}
