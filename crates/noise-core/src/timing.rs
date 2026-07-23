//! Human-like activity timing.
//!
//! Real users are not uniform: they sleep, they burst, they idle. We model activity
//! as a non-homogeneous Poisson process whose rate follows a circadian curve, plus
//! multiplicative jitter. This is what makes "wakes up at random human hours" real
//! instead of `sleep(rand)`.
//!
//! Honest limitation: on Solana, leader schedule is deterministic and latency is low,
//! so timing jitter is a WEAK signal on its own. Its value here is degrading *cross-tx
//! temporal correlation*, not hiding a single tx. See README threat model.

use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircadianModel {
    /// Relative activity weight for each hour of the day (index 0..24).
    pub hourly_weights: [f64; 24],
    /// Mean number of actions during a fully-active hour (Poisson intensity).
    pub actions_per_active_hour: f64,
    /// Multiplicative jitter fraction applied to each inter-arrival gap (0.0..1.0).
    pub jitter: f64,
}

impl Default for CircadianModel {
    fn default() -> Self {
        // A plausible waking human: quiet 00-07, ramp up daytime, peak evening.
        let hourly_weights = [
            0.05, 0.03, 0.02, 0.02, 0.03, 0.05, 0.15, 0.35, // 00-07
            0.6, 0.8, 0.9, 0.95, 0.85, 0.9, 0.95, 0.9, // 08-15
            0.85, 0.9, 1.0, 1.0, 0.95, 0.7, 0.4, 0.15, // 16-23
        ];
        CircadianModel {
            hourly_weights,
            actions_per_active_hour: 2.0,
            jitter: 0.35,
        }
    }
}

impl CircadianModel {
    /// Normalized probability of being active in the given hour.
    pub fn active_prob(&self, hour: u32) -> f64 {
        let sum: f64 = self.hourly_weights.iter().sum();
        if sum <= 0.0 {
            return 0.0;
        }
        self.hourly_weights[(hour % 24) as usize] / sum
    }

    /// Sample the delay (seconds) until this agent's next action, given the current
    /// second-of-day. Uses an exponential inter-arrival (Poisson process) scaled by the
    /// circadian rate, then applies jitter. Always returns at least 1 second.
    pub fn next_delay_secs(&self, second_of_day: u64, rng: &mut impl Rng) -> u64 {
        let hour = ((second_of_day / 3600) % 24) as usize;
        let w = self.hourly_weights[hour].max(0.01);
        let rate_per_hour = (self.actions_per_active_hour * w).max(0.05);
        let mean_gap = 3600.0 / rate_per_hour; // seconds between actions

        // Exponential inter-arrival: -ln(U) * mean.
        let u: f64 = rng.random::<f64>().clamp(1e-9, 1.0);
        let gap = -u.ln() * mean_gap;

        // Symmetric multiplicative jitter in [1-j, 1+j].
        let j = 1.0 + (rng.random::<f64>() * 2.0 - 1.0) * self.jitter;
        (gap * j).max(1.0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn delays_are_positive_and_night_is_slower_than_day() {
        let m = CircadianModel::default();
        let mut r = rand::rngs::StdRng::seed_from_u64(7);

        let night_hour = 3 * 3600;
        let day_hour = 18 * 3600;
        let sample = |sod: u64, r: &mut rand::rngs::StdRng| -> f64 {
            let n = 400;
            (0..n)
                .map(|_| m.next_delay_secs(sod, r) as f64)
                .sum::<f64>()
                / n as f64
        };
        let night_avg = sample(night_hour, &mut r);
        let day_avg = sample(day_hour, &mut r);
        assert!(night_avg > 0.0 && day_avg > 0.0);
        // Night activity is far rarer, so gaps are much longer.
        assert!(
            night_avg > day_avg,
            "night {night_avg} should exceed day {day_avg}"
        );
    }

    #[test]
    fn active_prob_sums_to_one() {
        let m = CircadianModel::default();
        let total: f64 = (0..24).map(|h| m.active_prob(h)).sum();
        assert!((total - 1.0).abs() < 1e-9);
    }
}
