use crate::error::YanyError;
use std::net::{IpAddr, SocketAddr};

pub const MAX_CANDIDATES: usize = 8;

pub fn p2p_proof(secret: &str, session_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(secret.as_bytes());
    hasher.update(session_id);
    hasher.update(b"yany-p2p-v1");
    let hash = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

pub fn parse_candidate(raw: &str) -> Result<SocketAddr, YanyError> {
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| YanyError::Invalid("bad candidate".into()))?;
    if !allowed_ip(addr.ip()) || addr.port() == 0 {
        return Err(YanyError::Invalid("candidate not allowed".into()));
    }
    Ok(addr)
}

pub fn sanitize_candidates(raw: &[String]) -> Result<Vec<SocketAddr>, YanyError> {
    if raw.len() > MAX_CANDIDATES {
        return Err(YanyError::Invalid("too many candidates".into()));
    }
    let mut out = Vec::new();
    for s in raw {
        let addr = parse_candidate(s)?;
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

pub fn allowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_link_local()
        }
        IpAddr::V6(v) => !v.is_unspecified() && !v.is_multicast() && !v.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_is_stable_and_secret_dependent() {
        let sid = [7u8; 16];
        let a = p2p_proof("abc", &sid);
        let b = p2p_proof("abc", &sid);
        let c = p2p_proof("abd", &sid);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn rejects_multicast_and_port_zero() {
        assert!(parse_candidate("224.0.0.1:80").is_err());
        assert!(parse_candidate("10.0.0.5:0").is_err());
        assert!(parse_candidate("10.0.0.5:7000").is_ok());
    }

    #[test]
    fn caps_candidate_list() {
        let too_many: Vec<String> = (1..=9).map(|i| format!("10.0.0.{i}:9")).collect();
        assert!(sanitize_candidates(&too_many).is_err());
    }
}
