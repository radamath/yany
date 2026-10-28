use thiserror::Error;

#[derive(Debug, Error)]
pub enum YanyError {
    #[error("{0}")]
    Invalid(String),
    #[error("authentication failed")]
    Auth,
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("payload too large ({0} bytes)")]
    TooLarge(usize),
    #[error("rate limited")]
    RateLimited,
    #[error("capture: {0}")]
    Capture(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("io: {0}")]
    Io(String),
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<std::io::Error> for YanyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<bincode::Error> for YanyError {
    fn from(value: bincode::Error) -> Self {
        Self::Protocol(value.to_string())
    }
}
