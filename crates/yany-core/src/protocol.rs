use crate::error::YanyError;
use crate::id::HostId;
use crate::join_token::sanitize_display_name;
use crate::{MAX_CONTROL_BYTES, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PEERS: usize = 512;
pub const MAX_JOIN_TOKEN_CHARS: usize = 64;

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
    Join {
        token: String,
        name: String,
        id: HostId,
    },
    JoinOk {
        id: HostId,
        token: String,
        valid_until_unix: u64,
    },
    JoinFail {
        message: String,
    },
    TokenRotated {
        token: String,
        valid_until_unix: u64,
    },
    PeerList {
        peers: Vec<PeerInfo>,
    },
    ConnectRequest {
        target: HostId,
        unattended: bool,
    },
    IncomingCall {
        from: HostId,
        from_name: String,
        session_id: [u8; 16],
        unattended: bool,
        session_secret: String,
    },
    Accept {
        session_id: [u8; 16],
    },
    Reject {
        session_id: [u8; 16],
        reason: String,
    },
    SessionReady {
        session_id: [u8; 16],
        session_secret: String,
    },
    SessionBind {
        session_id: [u8; 16],
        id: HostId,
    },
    Candidates {
        session_id: [u8; 16],
        addrs: Vec<String>,
    },
    Punch {
        session_id: [u8; 16],
        proof: [u8; 16],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerInfo {
    pub id: HostId,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Role {
    Host,
    Viewer,
    RelayAdmin,
    Agent,
    Session,
}

fn validate_session_secret(secret: &str) -> Result<(), YanyError> {
    if secret.len() < 32 || secret.len() > 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err(YanyError::Protocol("bad session secret".into()))
    } else {
        Ok(())
    }
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
            ControlMsg::RegisterHost { id }
            | ControlMsg::RegisterOk { id }
            | ControlMsg::Connect { target: id }
            | ControlMsg::ConnectRequest { target: id, .. }
            | ControlMsg::SessionBind { id, .. }
            | ControlMsg::IncomingCall { from: id, .. }
                if !id.is_valid() =>
            {
                Err(YanyError::Protocol("invalid host id".into()))
            }
            ControlMsg::Join { token, name, id } => {
                if !id.is_valid() {
                    return Err(YanyError::Protocol("invalid host id".into()));
                }
                if token.len() < 8 || token.len() > MAX_JOIN_TOKEN_CHARS {
                    return Err(YanyError::Protocol("bad join token".into()));
                }
                sanitize_display_name(name).map(|_| ())
            }
            ControlMsg::JoinOk { id, token, .. } => {
                if !id.is_valid() {
                    return Err(YanyError::Protocol("invalid host id".into()));
                }
                if token.len() < 8 || token.len() > MAX_JOIN_TOKEN_CHARS {
                    Err(YanyError::Protocol("bad join token".into()))
                } else {
                    Ok(())
                }
            }
            ControlMsg::TokenRotated { token, .. } => {
                if token.len() < 8 || token.len() > MAX_JOIN_TOKEN_CHARS {
                    Err(YanyError::Protocol("bad join token".into()))
                } else {
                    Ok(())
                }
            }
            ControlMsg::JoinFail { message } | ControlMsg::Reject { reason: message, .. }
                if message.len() > 256 =>
            {
                Err(YanyError::Protocol("reason too long".into()))
            }
            ControlMsg::PeerList { peers } => {
                if peers.len() > MAX_PEERS {
                    return Err(YanyError::Protocol("peer list too large".into()));
                }
                for p in peers {
                    if !p.id.is_valid() {
                        return Err(YanyError::Protocol("invalid host id".into()));
                    }
                    sanitize_display_name(&p.name)?;
                }
                Ok(())
            }
            ControlMsg::IncomingCall {
                from_name,
                from,
                session_secret,
                ..
            } => {
                if !from.is_valid() {
                    return Err(YanyError::Protocol("invalid host id".into()));
                }
                validate_session_secret(session_secret)?;
                sanitize_display_name(from_name).map(|_| ())
            }
            ControlMsg::SessionReady { session_secret, .. } => validate_session_secret(session_secret),
            ControlMsg::Candidates { addrs, .. } => {
                crate::candidate::sanitize_candidates(addrs).map(|_| ())
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

    #[test]
    fn join_rejects_bad_name_and_short_token() {
        let id = HostId::from_raw(123456789).unwrap();
        let bad = ControlMsg::Join {
            token: "abcd-ef01-2345-6789-aabb-ccdd-eeff-1032".into(),
            name: "no\npe".into(),
            id,
        };
        assert!(bad.validate().is_err());
        let short = ControlMsg::Join {
            token: "short".into(),
            name: "pc".into(),
            id,
        };
        assert!(short.validate().is_err());
        let ok = ControlMsg::Join {
            token: "abcd-ef01-2345-6789-aabb-ccdd-eeff-1032".into(),
            name: "pc-1".into(),
            id,
        };
        ok.validate().unwrap();
    }

    #[test]
    fn peer_list_caps_and_names() {
        let id = HostId::from_raw(123456789).unwrap();
        let msg = ControlMsg::PeerList {
            peers: vec![PeerInfo {
                id,
                name: "desk".into(),
            }],
        };
        msg.validate().unwrap();
        let too_many = ControlMsg::PeerList {
            peers: (0..MAX_PEERS + 1)
                .map(|_| PeerInfo {
                    id,
                    name: "desk".into(),
                })
                .collect(),
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn agent_hello_ok() {
        ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Agent,
        }
        .validate()
        .unwrap();
    }
}
