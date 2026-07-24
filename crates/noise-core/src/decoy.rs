//! Decoy / cover-traffic policy.
//!
//! For every real action an agent takes, we interleave a randomized number of decoy
//! actions (dust transfers, memos, throwaway interactions) so the real intent is not
//! obvious by volume or timing. Count is drawn around a configurable mean.
//!
//! Honest limitation: decoys are statistically weak against ML classifiers if they are
//! distinguishable from real actions. They only help when decoys are drawn from the
//! SAME distribution as real activity — which is why decoys reuse the persona's own
//! action/amount models. The `adversary` crate measures whether this actually works.

use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyPolicy {
    /// Mean number of decoy actions per real action.
    pub decoys_per_real: f64,
    /// Upper bound for dust-sized decoy amounts (lamports).
    pub dust_lamports_max: u64,
}

impl Default for DecoyPolicy {
    fn default() -> Self {
        DecoyPolicy {
            decoys_per_real: 1.5,
            dust_lamports_max: 50_000,
        }
    }
}

impl DecoyPolicy {
    /// Number of decoys to emit for one real action (Poisson-ish around the mean).
    pub fn num_decoys(&self, rng: &mut impl Rng) -> usize {
        if self.decoys_per_real <= 0.0 {
            return 0;
        }
        // Knuth's Poisson sampler.
        let l = (-self.decoys_per_real).exp();
        let mut k = 0usize;
        let mut p = 1.0f64;
        loop {
            k += 1;
            p *= rng.random::<f64>();
            if p <= l {
                break;
            }
            if k > 64 {
                break; // safety valve
            }
        }
        k - 1
    }

    /// A random dust amount for a decoy.
    pub fn dust_amount(&self, rng: &mut impl Rng) -> u64 {
        rng.random_range(1..=self.dust_lamports_max.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn decoy_mean_is_in_the_right_ballpark() {
        let policy = DecoyPolicy {
            decoys_per_real: 2.0,
            dust_lamports_max: 1000,
        };
        let mut r = rand::rngs::StdRng::seed_from_u64(3);
        let n = 5000;
        let mean = (0..n).map(|_| policy.num_decoys(&mut r)).sum::<usize>() as f64 / n as f64;
        assert!((mean - 2.0).abs() < 0.2, "mean was {mean}");
    }

    #[test]
    fn zero_rate_yields_no_decoys() {
        let policy = DecoyPolicy {
            decoys_per_real: 0.0,
            dust_lamports_max: 1000,
        };
        let mut r = rand::rngs::StdRng::seed_from_u64(1);
        assert_eq!(policy.num_decoys(&mut r), 0);
    }
}
