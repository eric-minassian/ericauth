use ericauth::jwt::generate_es256_keypair;

fn main() {
    let (private_pem, public_pem) =
        generate_es256_keypair().expect("Failed to generate ES256 keypair");

    println!("=== Private Key (store in Secrets Manager) ===");
    println!("{private_pem}");
    println!("=== Public Key (for reference) ===");
    println!("{public_pem}");
}
