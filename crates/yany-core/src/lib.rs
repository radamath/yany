//! Yany shared protocol, identity, capture/encode traits, and crypto.

pub mod auth;
pub mod capture;
pub mod config;
pub mod crypto;
pub mod encode;
pub mod error;
pub mod framing;
pub mod id;
pub mod input;
pub mod protocol;
pub mod rate_limit;
pub mod tile;

pub use config::CaptureKind;
pub use error::YanyError;
pub use id::HostId;
pub use protocol::{ControlMsg, Role, PROTOCOL_VERSION};

pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_TILE: u32 = 64;
