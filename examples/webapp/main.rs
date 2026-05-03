// Minimal Rust web application using KeyRack for encryption
//
// Demonstrates a simple HTTP service that encrypts and decrypts
// user data through the KeyRack gRPC API.
//
// Prerequisites:
//   1. keyrack-service running on localhost:50051
//   2. A namespace configured with appropriate rules
//
// Run: cargo run --example webapp

use std::collections::HashMap;

fn main() {
    println!("KeyRack Web Application Example");
    println!("================================\n");

    println!("This example demonstrates the integration pattern:");
    println!();
    println!("  1. Application receives user data via HTTP");
    println!("  2. Application calls KeyRack gRPC to encrypt sensitive fields");
    println!("  3. Encrypted data is stored in the application's database");
    println!("  4. On retrieval, application calls KeyRack gRPC to decrypt");
    println!();
    println!("Integration code (requires running keyrack-service):");
    println!();
    println!(r#"
    // Connect to KeyRack
    let mut client = KeyServiceClient::connect("http://localhost:50051").await?;

    // Encrypt user data before storing
    let resp = client.encrypt(EncryptRequest {{
        key_id: "user-data-key".into(),
        plaintext: sensitive_data.into(),
        encryption_context: HashMap::from([
            ("user_id".into(), user_id.into()),
            ("field".into(), "ssn".into()),
        ]),
    }}).await?;

    // Store resp.ciphertext in your database
    db.store(user_id, resp.into_inner().ciphertext).await?;

    // Later: decrypt when needed
    let resp = client.decrypt(DecryptRequest {{
        key_id: "user-data-key".into(),
        ciphertext: stored_ciphertext,
        encryption_context: HashMap::from([
            ("user_id".into(), user_id.into()),
            ("field".into(), "ssn".into()),
        ]),
    }}).await?;

    let plaintext = resp.into_inner().plaintext;
    "#);
}
