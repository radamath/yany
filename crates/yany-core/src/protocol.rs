use crate::error::YanyError;
use crate::id::HostId;
use crate::{MAX_CONTROL_BYTES, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlMsg {
    Hello {
        version: u16,
        role: Role,
    },
    RegisterHost {
        id: HostId,
    },
    RegisterOk {
        id: HostId,
    },
    Connect {
        target: HostId,
    },
    Incoming,
    Challenge {
        nonce: [u8; 32],
    },
    Auth {
        proof: Vec<u8>,
    },
    AuthOk,
    AuthFail,
    Frame {
        seq: u64,
        ciphertext: Vec<u8>,
    },
    Input {
        seq: u64,
        ciphertext: Vec<u8>,
    },
    Disconnect {
        reason: String,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    Host,
    Viewer,
    RelayAdmin,
}

impl ControlMsg {
    pub fn validate(&self) -> Result<(), YanyError> {
        match self {
            ControlMsg::Hello { version, .. } if *version != PROTOCOL_VERSION => {
                Err(YanyError::Protocol("unsupported version".into()))
            }
            ControlMsg::Auth { proof } if proof.len() > 128 => {
                Err(YanyError::Protocol("auth proof too long".into()))
            }
            ControlMsg::Input { ciphertext, .. }
                if ciphertext.is_empty() || ciphertext.len() > MAX_CONTROL_BYTES =>
            {
                Err(YanyError::Protocol("bad input".into()))
            }
            ControlMsg::Disconnect { reason } | ControlMsg::Error { message: reason }
                if reason.len() > 256 =>
            {
                Err(YanyError::Protocol("reason too long".into()))
            }
            ControlMsg::Frame { ciphertext, .. }
                if ciphertext.is_empty() || ciphertext.len() > MAX_FRAME_BYTES =>
            {
                Err(YanyError::Protocol("bad frame".into()))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_version() {
        let msg = ControlMsg::Hello {
            version: 99,
            role: Role::Host,
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn accepts_current_hello() {
        let msg = ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Viewer,
        };
        msg.validate().unwrap();
    }

    #[test]
    fn rejects_empty_frame() {
        let msg = ControlMsg::Frame {
            seq: 1,
            ciphertext: vec![],
        };
        assert!(msg.validate().is_err());
    }
}
