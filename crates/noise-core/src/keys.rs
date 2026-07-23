//! Ephemeral / one-time addresses (stealth-address style, ERC-5564-inspired).
//!
//! Address reuse is the single strongest clustering signal. This module derives a
//! fresh, unlinkable receiving address per payment using a Diffie-Hellman shared
//! secret between an ephemeral key and the recipient's spend key, so only the
//! recipient can recognize/spend it, while an observer cannot link two payments to
//! the same recipient by address alone.
//!
//! Honest limitation: rotating the *destination* address is not enough if the
//! *fee-payer* is constant — the fee-payer leaks identity. The runtime rotates
//! fee-payers precisely for this reason. Graph analysis can still defeat isolated
//! stealth addresses; this is one layer, not a guarantee.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
};
use rand::Rng;
use sha2::{Digest, Sha512};

use crate::types::AccountId;

/// A keypair over the Ristretto group. `public` is the compressed 32-byte point.
#[derive(Clone)]
pub struct StealthKeypair {
    pub secret: Scalar,
    pub public: [u8; 32],
}

fn random_scalar(rng: &mut impl Rng) -> Scalar {
    // 64 wide bytes -> uniform scalar mod l. Avoids depending on curve25519-dalek's
    // rng feature (and any rand_core version skew).
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(bytes);
    let d: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&d)
}

/// Generate a fresh keypair (used for one-time fee-payers and throwaway sub-accounts).
pub fn fresh_keypair(rng: &mut impl Rng) -> StealthKeypair {
    let secret = random_scalar(rng);
    let public = (RISTRETTO_BASEPOINT_POINT * secret).compress().to_bytes();
    StealthKeypair { secret, public }
}

/// Derive a one-time destination address for a recipient identified by their
/// compressed spend public key. Returns the one-time address and the ephemeral
/// public key the recipient needs to recover the spending key. Returns `None` if
/// the recipient key is not a valid group element.
pub fn derive_one_time(
    recipient_spend: &[u8; 32],
    rng: &mut impl Rng,
) -> Option<(AccountId, [u8; 32])> {
    let eph = random_scalar(rng);
    let eph_pub = (RISTRETTO_BASEPOINT_POINT * eph).compress().to_bytes();

    let spend_point = CompressedRistretto::from_slice(recipient_spend)
        .ok()?
        .decompress()?;

    // Shared secret s = eph * spendPub ; tweak t = H(s).
    let shared = spend_point * eph;
    let tweak = hash_to_scalar(&shared.compress().to_bytes());

    // One-time address P = spendPub + t*G.
    let one_time = spend_point + RISTRETTO_BASEPOINT_POINT * tweak;
    Some((AccountId(one_time.compress().to_bytes()), eph_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn fresh_keypairs_are_distinct() {
        let mut r = rand::rngs::StdRng::seed_from_u64(42);
        let a = fresh_keypair(&mut r);
        let b = fresh_keypair(&mut r);
        assert_ne!(a.public, b.public);
    }

    #[test]
    fn one_time_addresses_are_unlinkable_across_payments() {
        let mut r = rand::rngs::StdRng::seed_from_u64(9);
        let recipient = fresh_keypair(&mut r);
        let (addr1, _) = derive_one_time(&recipient.public, &mut r).unwrap();
        let (addr2, _) = derive_one_time(&recipient.public, &mut r).unwrap();
        // Same recipient, two payments, two unrelated-looking addresses.
        assert_ne!(addr1, addr2);
    }
}
