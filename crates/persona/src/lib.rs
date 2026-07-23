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
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonaValidationError {
    message: String,
}

impl PersonaValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PersonaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PersonaValidationError {}

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
    /// Reject malformed or unsafe profiles before a long-running fleet starts.
    pub fn validate(&self) -> Result<(), PersonaValidationError> {
        if self.name.trim().is_empty() {
            return Err(PersonaValidationError::new("name must not be empty"));
        }
        if self.wealth_tier.trim().is_empty() {
            return Err(PersonaValidationError::new("wealth_tier must not be empty"));
        }
        if self.base_amount_lamports == 0 {
            return Err(PersonaValidationError::new(
                "base_amount_lamports must be greater than zero",
            ));
        }
        if !self.amount_sigma.is_finite() || self.amount_sigma <= 0.0 {
            return Err(PersonaValidationError::new(
                "amount_sigma must be finite and greater than zero",
            ));
        }
        if self.num_subaccounts == 0 {
            return Err(PersonaValidationError::new(
                "num_subaccounts must be greater than zero",
            ));
        }
        if self.split.min_parts == 0 || self.split.max_parts < self.split.min_parts {
            return Err(PersonaValidationError::new(
                "split parts must satisfy 1 <= min_parts <= max_parts",
            ));
        }
        if self.split.min_part_lamports == 0 {
            return Err(PersonaValidationError::new(
                "split.min_part_lamports must be greater than zero",
            ));
        }
        if !self.decoy.decoys_per_real.is_finite() || self.decoy.decoys_per_real < 0.0 {
            return Err(PersonaValidationError::new(
                "decoy.decoys_per_real must be finite and non-negative",
            ));
        }
        if self.decoy.dust_lamports_max == 0 {
            return Err(PersonaValidationError::new(
                "decoy.dust_lamports_max must be greater than zero",
            ));
        }
        if !self.circadian.actions_per_active_hour.is_finite()
            || self.circadian.actions_per_active_hour <= 0.0
        {
            return Err(PersonaValidationError::new(
                "circadian.actions_per_active_hour must be finite and greater than zero",
            ));
        }
        if !self.circadian.jitter.is_finite() || !(0.0..=1.0).contains(&self.circadian.jitter) {
            return Err(PersonaValidationError::new(
                "circadian.jitter must be between 0 and 1",
            ));
        }
        if self
            .circadian
            .hourly_weights
            .iter()
            .any(|weight| !weight.is_finite() || *weight < 0.0)
            || !self
                .circadian
                .hourly_weights
                .iter()
                .any(|weight| *weight > 0.0)
        {
            return Err(PersonaValidationError::new(
                "circadian.hourly_weights must be finite, non-negative, and not all zero",
            ));
        }

        let mut recognized_positive_weight = false;
        for (key, weight) in &self.action_weights {
            if ActionKind::from_key(key).is_none() {
                return Err(PersonaValidationError::new(format!(
                    "unknown action_weights key '{key}'"
                )));
            }
            if !weight.is_finite() || *weight < 0.0 {
                return Err(PersonaValidationError::new(format!(
                    "action weight '{key}' must be finite and non-negative"
                )));
            }
            recognized_positive_weight |= *weight > 0.0;
        }
        if !recognized_positive_weight {
            return Err(PersonaValidationError::new(
                "at least one action weight must be greater than zero",
            ));
        }
        Ok(())
    }

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
            p.validate().unwrap();
            let s = toml::to_string(&p).unwrap();
            let back = Persona::from_toml_str(&s).unwrap();
            assert_eq!(back.name, p.name);
            assert_eq!(back.num_subaccounts, p.num_subaccounts);
        }
    }

    #[test]
    fn validation_rejects_unknown_actions_and_unsafe_values() {
        let mut p = Persona::retail();
        p.action_weights.insert("teleport".into(), 1.0);
        assert!(p.validate().unwrap_err().to_string().contains("teleport"));

        let mut p = Persona::retail();
        p.circadian.jitter = 1.5;
        assert!(p.validate().unwrap_err().to_string().contains("jitter"));

        let mut p = Persona::retail();
        p.num_subaccounts = 0;
        assert!(p
            .validate()
            .unwrap_err()
            .to_string()
            .contains("num_subaccounts"));
    }
}
