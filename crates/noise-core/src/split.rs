//! Value splitting: break one payment into N non-obvious parts that sum to the total.
//!
//! Destroys the "single unique amount" fingerprint that links a source to a
//! destination. Parts are randomly weighted (not equal) and never round.

use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitPolicy {
    pub min_parts: usize,
    pub max_parts: usize,
    /// Never emit a part smaller than this (avoids dust that itself becomes a fingerprint).
    pub min_part_lamports: u64,
}

impl Default for SplitPolicy {
    fn default() -> Self {
        SplitPolicy {
            min_parts: 2,
            max_parts: 5,
            min_part_lamports: 10_000,
        }
    }
}

/// Split `total` into parts that sum EXACTLY to `total`, each `>= min_part_lamports`,
/// with a randomly chosen count in `[min_parts, max_parts]` (clamped to what is feasible).
pub fn split_amount(total: u64, policy: &SplitPolicy, rng: &mut impl Rng) -> Vec<u64> {
    if total == 0 {
        return vec![];
    }
    let base = policy.min_part_lamports.max(1);
    if total <= base {
        return vec![total];
    }

    // How many parts of at least `base` can we afford?
    let feasible = (total / base).max(1) as usize;
    let max_parts = policy.max_parts.max(1).min(feasible);
    let min_parts = policy.min_parts.clamp(1, max_parts);
    let n = if min_parts >= max_parts {
        max_parts
    } else {
        rng.random_range(min_parts..=max_parts)
    };

    // Seed each part at the floor, then distribute the remainder by random weights.
    let mut parts = vec![base; n];
    let remainder = total - base * n as u64;
    let weights: Vec<f64> = (0..n).map(|_| rng.random::<f64>() + 0.01).collect();
    let wsum: f64 = weights.iter().sum();
    for (i, w) in weights.iter().enumerate() {
        parts[i] += ((w / wsum) * remainder as f64) as u64;
    }

    // Push any rounding leftover onto a random part so the sum is exact.
    let assigned: u64 = parts.iter().sum();
    let leftover = total - assigned;
    let idx = rng.random_range(0..n);
    parts[idx] += leftover;

    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng(seed: u64) -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(seed)
    }

    #[test]
    fn parts_sum_to_total_and_respect_floor() {
        let policy = SplitPolicy::default();
        for seed in 0..200u64 {
            let mut r = rng(seed);
            let total = 10_000 + (seed * 7_919) % 5_000_000;
            let parts = split_amount(total, &policy, &mut r);
            assert_eq!(parts.iter().sum::<u64>(), total, "seed {seed}");
            assert!(
                parts.len()
                    >= policy
                        .min_parts
                        .min((total / policy.min_part_lamports) as usize)
            );
            assert!(parts
                .iter()
                .all(|&p| p >= policy.min_part_lamports || parts.len() == 1));
        }
    }

    #[test]
    fn tiny_amount_is_not_split() {
        let policy = SplitPolicy::default();
        let mut r = rng(1);
        assert_eq!(split_amount(5_000, &policy, &mut r), vec![5_000]);
        assert!(split_amount(0, &policy, &mut r).is_empty());
    }
}
