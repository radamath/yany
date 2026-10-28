use crate::error::YanyError;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    window: Duration,
    max_hits: u32,
    hits: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(window: Duration, max_hits: u32) -> Result<Self, YanyError> {
        if max_hits == 0 || window.is_zero() {
            return Err(YanyError::Invalid("rate limiter config".into()));
        }
        Ok(Self {
            window,
            max_hits,
            hits: HashMap::new(),
        })
    }

    pub fn check(&mut self, key: &str) -> Result<(), YanyError> {
        if key.len() > 128 {
            return Err(YanyError::Invalid("rate-limit key too long".into()));
        }
        let now = Instant::now();
        let entries = self.hits.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() as u32 >= self.max_hits {
            return Err(YanyError::RateLimited);
        }
        entries.push(now);
        if self.hits.len() > 10_000 {
            self.hits.retain(|_, v| !v.is_empty());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_then_blocks() {
        let mut lim = RateLimiter::new(Duration::from_secs(60), 2).unwrap();
        lim.check("1.1.1.1").unwrap();
        lim.check("1.1.1.1").unwrap();
        assert!(matches!(lim.check("1.1.1.1"), Err(YanyError::RateLimited)));
        lim.check("2.2.2.2").unwrap();
    }
}
