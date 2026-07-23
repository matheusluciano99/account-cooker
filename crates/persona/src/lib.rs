//! Personas describe *believable* behavior: an action mix, a spend distribution, a
//! circadian rhythm, and noise policies. They are declarative (TOML) so new profiles
//! are added without touching code — the customization the bounty asks for.

use noise_core::decoy::DecoyPolicy;
use noise_core::split::SplitPolicy;
use noise_core::timing::CircadianModel;
use noise_core::types::ActionKind;
use rand::{Rng, RngExt};
use rand_distr::{Distribution, LogNormal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Persona {
    pub name: String,
    pub wealth_tier: String,
    #[serde(default)]
    pub circadian: CircadianModel,
    #[serde(default)]
    pub split: SplitPolicy,
    #[serde(default)]
    pub decoy: DecoyPolicy,
    pub base_amount_lamports: u64,
    #[serde(default = "default_sigma")]
    pub amount_sigma: f64,
    pub num_subaccounts: usize,
    /// Weight table keyed by `ActionKind::key()` (e.g. "transfer" -> 0.55).
    pub action_weights: BTreeMap<String, f64>,
}

fn default_sigma() -> f64 {
    0.6
}

impl Persona {
    /// Weighted pick of the next action kind. Falls back to `Transfer` if the table is empty.
    pub fn choose_action(&self, rng: &mut impl Rng) -> ActionKind {
        let total: f64 = self
            .action_weights
            .values()
            .copied()
            .filter(|w| *w > 0.0)
            .sum();
        if total <= 0.0 {
            return ActionKind::Transfer;
        }
        let mut pick = rng.random::<f64>() * total;
        for (k, w) in &self.action_weights {
            if *w <= 0.0 {
                continue;
            }
            pick -= *w;
            if pick <= 0.0 {
                if let Some(a) = ActionKind::from_key(k) {
                    return a;
                }
            }
        }
        ActionKind::Transfer
    }

    /// Sample a plausible amount (lamports) from a log-normal around the base.
    pub fn sample_amount(&self, rng: &mut impl Rng) -> u64 {
        let base = self.base_amount_lamports.max(1) as f64;
        match LogNormal::new(base.ln(), self.amount_sigma.max(0.01)) {
            Ok(d) => d.sample(rng).round().max(1.0) as u64,
            Err(_) => self.base_amount_lamports.max(1),
        }
    }

    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    fn weights(pairs: &[(ActionKind, f64)]) -> BTreeMap<String, f64> {
        pairs
            .iter()
            .map(|(k, w)| (k.key().to_string(), *w))
            .collect()
    }

    pub fn retail() -> Self {
        Persona {
            name: "retail".into(),
            wealth_tier: "retail".into(),
            circadian: CircadianModel::default(),
            split: SplitPolicy {
                min_parts: 2,
                max_parts: 4,
                min_part_lamports: 50_000,
            },
            decoy: DecoyPolicy {
                decoys_per_real: 1.0,
                dust_lamports_max: 30_000,
            },
            base_amount_lamports: 2_000_000,
            amount_sigma: 0.7,
            num_subaccounts: 4,
            action_weights: Self::weights(&[
                (ActionKind::Transfer, 0.55),
                (ActionKind::Swap, 0.25),
                (ActionKind::Stake, 0.10),
                (ActionKind::Memo, 0.10),
            ]),
        }
    }

    pub fn whale() -> Self {
        Persona {
            name: "whale".into(),
            wealth_tier: "whale".into(),
            circadian: CircadianModel::default(),
            split: SplitPolicy {
                min_parts: 3,
                max_parts: 6,
                min_part_lamports: 1_000_000,
            },
            decoy: DecoyPolicy {
                decoys_per_real: 2.0,
                dust_lamports_max: 200_000,
            },
            base_amount_lamports: 500_000_000,
            amount_sigma: 0.5,
            num_subaccounts: 8,
            action_weights: Self::weights(&[
                (ActionKind::Transfer, 0.30),
                (ActionKind::Swap, 0.40),
                (ActionKind::Stake, 0.20),
                (ActionKind::Memo, 0.10),
            ]),
        }
    }

    pub fn market_maker() -> Self {
        Persona {
            name: "market_maker".into(),
            wealth_tier: "mm".into(),
            circadian: CircadianModel {
                // MMs are active around the clock; flatter curve.
                hourly_weights: [0.6; 24],
                actions_per_active_hour: 5.0,
                jitter: 0.25,
            },
            split: SplitPolicy {
                min_parts: 2,
                max_parts: 5,
                min_part_lamports: 500_000,
            },
            decoy: DecoyPolicy {
                decoys_per_real: 2.5,
                dust_lamports_max: 100_000,
            },
            base_amount_lamports: 50_000_000,
            amount_sigma: 0.4,
            num_subaccounts: 6,
            action_weights: Self::weights(&[
                (ActionKind::Swap, 0.60),
                (ActionKind::Transfer, 0.30),
                (ActionKind::Memo, 0.10),
            ]),
        }
    }

    /// Built-in presets so tooling runs with zero external config.
    pub fn presets() -> Vec<Persona> {
        vec![Self::retail(), Self::whale(), Self::market_maker()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn choose_action_respects_weights() {
        let p = Persona::market_maker();
        let mut r = rand::rngs::StdRng::seed_from_u64(11);
        let n = 4000;
        let swaps = (0..n)
            .filter(|_| p.choose_action(&mut r) == ActionKind::Swap)
            .count();
        // MM swaps 60% of the time; allow slack.
        assert!(swaps as f64 / n as f64 > 0.5);
    }

    #[test]
    fn presets_serialize_to_toml_and_back() {
        for p in Persona::presets() {
            let s = toml::to_string(&p).unwrap();
            let back = Persona::from_toml_str(&s).unwrap();
            assert_eq!(back.name, p.name);
            assert_eq!(back.num_subaccounts, p.num_subaccounts);
        }
    }
}
