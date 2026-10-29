use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use yany_core::framing::{decode_body, encode_msg, peek_len, read_msg, write_msg};
use yany_core::protocol::ControlMsg;

const MAGIC: &[u8; 4] = b"YNYU";
const KIND_PUNCH: u8 = 0;
const KIND_MSG: u8 = 1;
const MAX_FRAG: usize = 1100;
const MAX_FRAGS: u16 = 2048;

pub trait MsgPipe: Send {
    fn send_msg(
        &mut self,
        msg: &ControlMsg,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn recv_msg(&mut self) -> impl std::future::Future<Output = Result<ControlMsg>> + Send;
}

pub struct StreamPipe<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R, W> MsgPipe for StreamPipe<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send_msg(&mut self, msg: &ControlMsg) -> Result<()> {
        write_msg(&mut self.writer, msg).await?;
        Ok(())
    }

    async fn recv_msg(&mut self) -> Result<ControlMsg> {
        Ok(read_msg(&mut self.reader).await?)
    }
}

pub struct UdpSend {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    next_send: u64,
}

pub struct UdpRecv {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    parts: HashMap<u64, FragBuf>,
}

pub struct UdpPipe {
    send: UdpSend,
    recv: UdpRecv,
}

struct FragBuf {
    need: u16,
    got: Vec<Option<Vec<u8>>>,
}

impl UdpPipe {
    pub fn new(sock: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self {
            send: UdpSend {
                sock: sock.clone(),
                peer,
                next_send: 1,
            },
            recv: UdpRecv {
                sock,
                peer,
                parts: HashMap::new(),
            },
        }
    }

    pub fn into_split(self) -> (UdpRecv, UdpSend) {
        (self.recv, self.send)
    }
}

impl UdpSend {
    pub async fn send_msg(&mut self, msg: &ControlMsg) -> Result<()> {
        let bytes = encode_msg(msg)?;
        let n = bytes.len().div_ceil(MAX_FRAG) as u16;
        if n == 0 || n > MAX_FRAGS {
            bail!("udp message too large");
        }
        let seq = self.next_send;
        self.next_send = self.next_send.wrapping_add(1);
        if self.next_send == 0 {
            self.next_send = 1;
        }
        for i in 0..n {
            let start = i as usize * MAX_FRAG;
            let end = (start + MAX_FRAG).min(bytes.len());
            let mut pkt = Vec::with_capacity(17 + end - start);
            pkt.extend_from_slice(MAGIC);
            pkt.push(KIND_MSG);
            pkt.extend_from_slice(&seq.to_le_bytes());
            pkt.extend_from_slice(&i.to_le_bytes());
            pkt.extend_from_slice(&n.to_le_bytes());
            pkt.extend_from_slice(&bytes[start..end]);
            self.sock.send_to(&pkt, self.peer).await?;
        }
        Ok(())
    }
}

impl UdpRecv {
    pub async fn recv_msg(&mut self) -> Result<ControlMsg> {
        loop {
            let mut buf = [0u8; 1400];
            let (n, from) = self.sock.recv_from(&mut buf).await?;
            if from != self.peer || n < 17 || &buf[..4] != MAGIC || buf[4] != KIND_MSG {
                continue;
            }
            let seq = u64::from_le_bytes(buf[5..13].try_into()?);
            let idx = u16::from_le_bytes(buf[13..15].try_into()?);
            let cnt = u16::from_le_bytes(buf[15..17].try_into()?);
            if cnt == 0 || cnt > MAX_FRAGS || idx >= cnt {
                continue;
            }
            let entry = self.parts.entry(seq).or_insert_with(|| FragBuf {
                need: cnt,
                got: vec![None; cnt as usize],
            });
            if entry.need != cnt || idx as usize >= entry.got.len() {
                continue;
            }
            entry.got[idx as usize] = Some(buf[17..n].to_vec());
            if !entry.got.iter().all(|p| p.is_some()) {
                continue;
            }
            let mut full = Vec::new();
            for part in entry.got.iter().flatten() {
                full.extend_from_slice(part);
            }
            self.parts.remove(&seq);
            self.parts.retain(|s, _| *s > seq.saturating_sub(4));
            if full.len() < 4 {
                continue;
            }
            let body_len = peek_len(full[..4].try_into()?)?;
            if full.len() < 4 + body_len {
                continue;
            }
            return Ok(decode_body(&full[4..4 + body_len])?);
        }
    }
}

impl MsgPipe for UdpPipe {
    async fn send_msg(&mut self, msg: &ControlMsg) -> Result<()> {
        self.send.send_msg(msg).await
    }

    async fn recv_msg(&mut self) -> Result<ControlMsg> {
        self.recv.recv_msg().await
    }
}

pub fn punch_packet(session_id: &[u8; 16], proof: &[u8; 16]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(37);
    pkt.extend_from_slice(MAGIC);
    pkt.push(KIND_PUNCH);
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(proof);
    pkt
}

pub fn parse_punch(buf: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    if buf.len() < 37 || &buf[..4] != MAGIC || buf[4] != KIND_PUNCH {
        return None;
    }
    let mut sid = [0u8; 16];
    let mut proof = [0u8; 16];
    sid.copy_from_slice(&buf[5..21]);
    proof.copy_from_slice(&buf[21..37]);
    Some((sid, proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_roundtrip() {
        let sid = [1u8; 16];
        let proof = [2u8; 16];
        let pkt = punch_packet(&sid, &proof);
        assert_eq!(parse_punch(&pkt), Some((sid, proof)));
        assert!(parse_punch(&pkt[..10]).is_none());
    }
}
