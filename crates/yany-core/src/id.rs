use crate::error::YanyError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// 9-digit public host identity. Not sequential; generated from CSPRNG.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HostId(u32);

impl HostId {
    pub const MIN: u32 = 100_000_000;
    pub const MAX: u32 = 999_999_999;

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        loop {
            let n = rng.next_u32() % 1_000_000_000;
            if n >= Self::MIN {
                return Self(n);
            }
        }
    }

    pub fn from_raw(n: u32) -> Result<Self, YanyError> {
        if (Self::MIN..=Self::MAX).contains(&n) {
            Ok(Self(n))
        } else {
            Err(YanyError::Invalid("host id must be 9 digits".into()))
        }
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn display_groups(self) -> String {
        let s = format!("{:09}", self.0);
        format!("{} {} {}", &s[0..3], &s[3..6], &s[6..9])
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_groups())
    }
}

impl FromStr for HostId {
    type Err = YanyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 9 {
            return Err(YanyError::Invalid("host id must be 9 digits".into()));
        }
        let n: u32 = digits
            .parse()
            .map_err(|_| YanyError::Invalid("host id parse".into()))?;
        Self::from_raw(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_nine_digits() {
        for _ in 0..32 {
            let id = HostId::generate();
            assert!(id.raw() >= HostId::MIN);
            assert_eq!(id.display_groups().chars().filter(|c| c.is_ascii_digit()).count(), 9);
        }
    }

    #[test]
    fn parse_accepts_grouped_and_plain() {
        let id = HostId::from_raw(123456789).unwrap();
        assert_eq!("123 456 789".parse::<HostId>().unwrap(), id);
        assert_eq!("123456789".parse::<HostId>().unwrap(), id);
    }

    #[test]
    fn rejects_short_and_leading_zero_range() {
        assert!("12345678".parse::<HostId>().is_err());
        assert!(HostId::from_raw(99999999).is_err());
        assert!("abcdefghi".parse::<HostId>().is_err());
    }
}
