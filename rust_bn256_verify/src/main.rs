use bls_signatures_rs::bn256::Bn256;
use bls_signatures_rs::MultiSignature;
use sha3::{Digest, Keccak256};

fn main() {
    // Inputs: Secret Key, Public Key (derived) & Message

    // Secret key one
    let secret_key_1 =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    // Secret key two
    let secret_key_2 =
        hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();

    // Derive public keys from secret key
    let public_key_1 = Bn256.derive_public_key(&secret_key_1).unwrap();
    let public_key_2 = Bn256.derive_public_key(&secret_key_2).unwrap();

    let message: &[u8] = b"sample";

    // Sign identical message with two different secret keys
    let sig_1 = Bn256.sign(&secret_key_1, &message).unwrap();
    let sig_2 = Bn256.sign(&secret_key_2, &message).unwrap();

    // Aggregate public keys
    let agg_pub_key = Bn256.aggregate_public_keys(&[&public_key_1, &public_key_2]).unwrap();

    // Aggregate signatures
    let agg_sig = Bn256.aggregate_signatures(&[&sig_1, &sig_2]).unwrap();

    // Check whether the aggregated signature corresponds to the aggregated public key
    let beta = Bn256.verify(&agg_sig, &message, &agg_pub_key).unwrap();

    // Use Keccak256 to hash the message
    let mut hasher = Keccak256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Print lengths
    println!("Public Key 1 Length: {}", public_key_1.len());
    println!("Public Key 2 Length: {}", public_key_2.len());
    println!("Signature 1 Length: {}", sig_1.len());
    println!("Signature 2 Length: {}", sig_2.len());
    
    println!("Aggregated Public Key Length: {}", agg_pub_key.len());
    println!("Aggregated Signature Length: {}", agg_sig.len());
    println!("");
    // Extract x and y coordinates from public keys (assuming compressed format)
    if public_key_1.len() == 65 {
        let public_key_1_x = &public_key_1[1..33]; // Skip prefix byte, first 32 bytes for x
        let public_key_1_y = &public_key_1[33..65]; // Next 32 bytes for y
        println!("Public Key 1 X: 0x{}", hex::encode(public_key_1_x));
        println!("Public Key 1 Y: 0x{}", hex::encode(public_key_1_y));
    } else {
        println!("Public Key 1 does not have the expected length");
    }

    if public_key_2.len() == 65 {
        let public_key_2_x = &public_key_2[1..33]; // Skip prefix byte, first 32 bytes for x
        let public_key_2_y = &public_key_2[33..65]; // Next 32 bytes for y
        println!("Public Key 2 X: 0x{}", hex::encode(public_key_2_x));
        println!("Public Key 2 Y: 0x{}", hex::encode(public_key_2_y));
    } else {
        println!("Public Key 2 does not have the expected length");
    }

    println!("Message Hash: 0x{}", hex::encode(message_hash));

    // Handle signatures and aggregated signatures with 33 bytes
    if sig_1.len() == 33 {
        let sig_1_r = &sig_1[1..33]; // Assuming 32 bytes are used for r, and 1 byte is a prefix
        // Signature typically has r and s components, here it might be in a different format
        println!("Signature 1 R: 0x{}", hex::encode(sig_1_r));
        // Handle s if it exists or adjust as needed
    } else {
        println!("Signature 1 does not have the expected length");
    }

    if sig_2.len() == 33 {
        let sig_2_r = &sig_2[1..33]; // Assuming 32 bytes are used for r, and 1 byte is a prefix
        // Signature typically has r and s components, here it might be in a different format
        println!("Signature 2 R: 0x{}", hex::encode(sig_2_r));
        // Handle s if it exists or adjust as needed
    } else {
        println!("Signature 2 does not have the expected length");
    }

    if agg_pub_key.len() == 65 {
        let agg_pub_key_x = &agg_pub_key[1..33]; // Skip prefix byte, first 32 bytes for x
        let agg_pub_key_y = &agg_pub_key[33..65]; // Next 32 bytes for y
        println!("");
        println!("Aggregated Public Key X: 0x{}", hex::encode(agg_pub_key_x));
        println!("Aggregated Public Key Y: 0x{}", hex::encode(agg_pub_key_y));
    } else {
        println!("Aggregated Public Key does not have the expected length");
    }

    if agg_sig.len() == 33 {
        let agg_sig_r = &agg_sig[1..33]; // Assuming 32 bytes are used for r, and 1 byte is a prefix
        // Handle s if it exists or adjust as needed
        println!("Aggregated Signature R: 0x{}", hex::encode(agg_sig_r));
    } else {
        println!("Aggregated Signature does not have the expected length");
    }

    println!("Successful verification");
}
