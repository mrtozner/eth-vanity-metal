use secp256k1::{SecretKey, PublicKey, Scalar, SECP256K1};
use tiny_keccak::{Hasher, Keccak};
use rand::RngCore;

/// Generate a random secp256k1 keypair using the global context
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    SECP256K1.generate_keypair(&mut rand::thread_rng())
}

/// Generate a keypair directly from random bytes (fastest method)
/// This is the preferred method for vanity address generation
/// Uses the global secp256k1 context for maximum performance
#[inline(always)]
pub fn generate_keypair_direct() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let pk = PublicKey::from_secret_key(&SECP256K1, &sk);
            return (sk, pk);
        }
    }
}

/// Get raw 20-byte Ethereum address (before hex encoding)
#[inline(always)]
pub fn public_key_to_raw_address(public_key: &PublicKey) -> [u8; 20] {
    let public_key_bytes = public_key.serialize_uncompressed();

    let mut keccak = Keccak::v256();
    keccak.update(&public_key_bytes[1..]);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..32]);
    address_bytes
}

/// Convert a public key to an Ethereum address
///
/// The process:
/// 1. Take uncompressed public key (65 bytes, skip first byte 0x04)
/// 2. Keccak-256 hash the remaining 64 bytes
/// 3. Take last 20 bytes of the hash
/// 4. Format as "0x" + hex
pub fn public_key_to_eth_address(public_key: &PublicKey) -> String {
    let address_bytes = public_key_to_raw_address(public_key);
    format!("0x{}", hex::encode(address_bytes))
}

/// Convert a secret key to hex string
pub fn private_key_to_hex(secret_key: &SecretKey) -> String {
    hex::encode(secret_key.secret_bytes())
}

/// `address` may include a `0x` prefix. All constraints are ANDed; omitted constraints are ignored.
/// Returns false if both `prefix` and `suffix` are `None`.
pub fn eth_address_matches_patterns(
    address: &str,
    prefix: Option<&str>,
    suffix: Option<&str>,
) -> bool {
    if prefix.is_none() && suffix.is_none() {
        return false;
    }
    let body = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address)
        .to_lowercase();
    let prefix_ok = prefix.map_or(true, |p| body.starts_with(&p.to_lowercase()));
    let suffix_ok = suffix.map_or(true, |s| body.ends_with(&s.to_lowercase()));
    prefix_ok && suffix_ok
}

/// Sequential keypair generator - MUCH faster than random generation!
///
/// Instead of generating a random private key for every attempt (which requires
/// expensive scalar multiplication k × G), this generator:
/// 1. Starts with one random keypair (k, P) where P = k × G
/// 2. For each subsequent key, performs point addition: P_next = P_prev + G
/// 3. Increments the private key: k_next = k_prev + 1
///
/// Point addition is ~100x faster than scalar multiplication!
pub struct SequentialGenerator {
    current_secret: SecretKey,
    current_public: PublicKey,
    one: Scalar, // Pre-computed scalar for incrementing
}

impl SequentialGenerator {
    /// Create a new sequential generator starting from a random point
    #[inline(always)]
    pub fn new() -> Self {
        let (secret, public) = generate_keypair_direct();

        // Pre-compute scalar "1" for maximum performance
        let one = Scalar::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]).expect("scalar 1 is valid");

        Self {
            current_secret: secret,
            current_public: public,
            one,
        }
    }

    /// Get the next keypair in sequence
    /// This uses FAST point addition instead of SLOW scalar multiplication
    #[inline(always)]
    pub fn next(&mut self) -> (&SecretKey, &PublicKey) {
        // FAST: Add G to current public key (point addition)
        // This is the key optimization - ~100x faster than scalar multiplication!
        self.current_public = self.current_public
            .add_exp_tweak(&SECP256K1, &self.one)
            .expect("valid point addition");

        // FAST: Increment secret key by 1 (scalar addition)
        self.current_secret = self.current_secret
            .add_tweak(&self.one)
            .expect("valid scalar addition");

        (&self.current_secret, &self.current_public)
    }

    /// Get current keypair without advancing
    #[inline(always)]
    pub fn current(&self) -> (&SecretKey, &PublicKey) {
        (&self.current_secret, &self.current_public)
    }
}

impl Default for SequentialGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_generation() {
        let (secret_key, public_key) = generate_keypair();
        let address = public_key_to_eth_address(&public_key);

        // Ethereum addresses start with '0x' and are 42 characters long
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);

        // Private key should be 64 hex characters
        let private_hex = private_key_to_hex(&secret_key);
        assert_eq!(private_hex.len(), 64);
    }

    #[test]
    fn test_sequential_generator() {
        let mut gen = SequentialGenerator::new();

        // Get first address
        let addr1 = {
            let (sk, pk) = gen.current();
            let addr = public_key_to_eth_address(pk);
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
            addr
        };

        // Get next address
        let addr2 = {
            let (sk, pk) = gen.next();
            let addr = public_key_to_eth_address(pk);
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
            addr
        };

        // Addresses should be different
        assert_ne!(addr1, addr2);

        // Generate a few more to ensure it keeps working
        for _ in 0..100 {
            let (sk, pk) = gen.next();
            let addr = public_key_to_eth_address(pk);

            // Should always start with '0x' and be 42 chars
            assert!(addr.starts_with("0x"));
            assert_eq!(addr.len(), 42);

            // Private key should be valid
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
        }
    }

    #[test]
    fn test_known_vector() {
        // Known Ethereum test vector
        // Verified using eth_account library (Python)
        let private_key_hex = "4c0883a69102937d6231471b5dbb6204fe512961708279f8b9f0629fbd2b6f72";
        let expected_address = "0x4fa9eef32a1e34e6f6384f30719feb18ea9563bc";

        let private_bytes = hex::decode(private_key_hex).unwrap();
        let secret_key = SecretKey::from_slice(&private_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);
        let address = public_key_to_eth_address(&public_key);

        // Ethereum addresses are case-insensitive for comparison
        assert_eq!(address.to_lowercase(), expected_address.to_lowercase());
    }
}
