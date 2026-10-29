use crate::pipe::{punch_packet, parse_punch, MsgPipe, StreamPipe, UdpPipe};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use yany_core::auth::random_bytes;
use yany_core::candidate::{allowed_ip, p2p_proof, sanitize_candidates};
use yany_core::protocol::ControlMsg;

pub enum Direct {
    Tcp(StreamPipe<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>),
    Udp(UdpPipe),
}

impl MsgPipe for Direct {
    async fn send_msg(&mut self, msg: &ControlMsg) -> Result<()> {
        match self {
            Direct::Tcp(p) => p.send_msg(msg).await,
            Direct::Udp(p) => p.send_msg(msg).await,
        }
    }

    async fn recv_msg(&mut self) -> Result<ControlMsg> {
        match self {
            Direct::Tcp(p) => p.recv_msg().await,
            Direct::Udp(p) => p.recv_msg().await,
        }
    }
}

pub async fn try_direct(
    session_id: [u8; 16],
    secret: &str,
    announce: mpsc::Sender<ControlMsg>,
    mut peer_rx: mpsc::Receiver<Vec<String>>,
) -> Option<Direct> {
    let proof = p2p_proof(secret, &session_id);
    let tcp = TcpListener::bind("0.0.0.0:0").await.ok()?;
    let udp = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let tcp_port = tcp.local_addr().ok()?.port();
    let udp_port = udp.local_addr().ok()?.port();
    let local = default_ipv4();
    let mut addrs = Vec::new();
    if let Some(ip) = local {
        addrs.push(format!("{ip}:{tcp_port}"));
        addrs.push(format!("{ip}:{udp_port}"));
    }
    addrs.truncate(8);
    if addrs.is_empty() {
        return None;
    }
    let _ = announce
        .send(ControlMsg::Candidates {
            session_id,
            addrs: addrs.clone(),
        })
        .await;
    let peer_addrs = tokio::time::timeout(Duration::from_millis(400), peer_rx.recv())
        .await
        .ok()
        .flatten()
        .and_then(|raw| sanitize_candidates(&raw).ok())
        .unwrap_or_default();
    if peer_addrs.is_empty() {
        return None;
    }
    let self_addrs: Vec<SocketAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
    let udp = Arc::new(udp);
    race(session_id, proof, tcp, udp, peer_addrs, self_addrs).await
}

async fn race(
    session_id: [u8; 16],
    proof: [u8; 16],
    tcp: TcpListener,
    udp: Arc<UdpSocket>,
    peers: Vec<SocketAddr>,
    self_addrs: Vec<SocketAddr>,
) -> Option<Direct> {
    let punch = punch_packet(&session_id, &proof);
    let (tx, mut rx) = mpsc::channel::<Direct>(1);
    let tx_accept = tx.clone();
    tokio::spawn(async move {
        if let Ok((stream, _)) = tcp.accept().await {
            if let Some(pipe) = verify_tcp(stream, session_id, proof).await {
                let _ = tx_accept.send(Direct::Tcp(pipe)).await;
            }
        }
    });
    for addr in &peers {
        let addr = *addr;
        let tx = tx.clone();
        tokio::spawn(async move {
            let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_millis(900), TcpStream::connect(addr)).await
            else {
                return;
            };
            if let Some(pipe) = offer_tcp(stream, session_id, proof).await {
                let _ = tx.send(Direct::Tcp(pipe)).await;
            }
        });
        let sock = udp.clone();
        let pkt = punch.clone();
        tokio::spawn(async move {
            for _ in 0..8 {
                let _ = sock.send_to(&pkt, addr).await;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        });
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut buf = [0u8; 64];
        tokio::select! {
            d = rx.recv() => return d,
            pkt = udp.recv_from(&mut buf) => {
                let Ok((n, from)) = pkt else { continue; };
                if self_addrs.iter().any(|a| a.ip() == from.ip()) {
                    continue;
                }
                let Some((sid, got)) = parse_punch(&buf[..n]) else { continue; };
                if sid != session_id || got != proof {
                    continue;
                }
                let _ = udp.send_to(&punch, from).await;
                return Some(Direct::Udp(UdpPipe::new(udp, from)));
            }
        }
    }
}

async fn offer_tcp(
    stream: TcpStream,
    session_id: [u8; 16],
    proof: [u8; 16],
) -> Option<StreamPipe<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>> {
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();
    let mut pipe = StreamPipe { reader, writer };
    pipe.send_msg(&ControlMsg::Punch { session_id, proof })
        .await
        .ok()?;
    match pipe.recv_msg().await.ok()? {
        ControlMsg::Punch {
            session_id: sid,
            proof: got,
        } if sid == session_id && got == proof => Some(pipe),
        _ => None,
    }
}

async fn verify_tcp(
    stream: TcpStream,
    session_id: [u8; 16],
    proof: [u8; 16],
) -> Option<StreamPipe<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>> {
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();
    let mut pipe = StreamPipe { reader, writer };
    match pipe.recv_msg().await.ok()? {
        ControlMsg::Punch {
            session_id: sid,
            proof: got,
        } if sid == session_id && got == proof => {}
        _ => return None,
    }
    pipe.send_msg(&ControlMsg::Punch { session_id, proof })
        .await
        .ok()?;
    Some(pipe)
}

fn default_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v) if allowed_ip(IpAddr::V4(v)) && !v.is_loopback() => Some(v),
        _ => None,
    }
}

#[allow(dead_code)]
async fn stun_mapped(sock: &UdpSocket) -> Option<SocketAddr> {
    let txid = random_bytes::<12>();
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    req[8..20].copy_from_slice(&txid);
    sock.send_to(&req, "stun.l.google.com:19302").await.ok()?;
    let mut buf = [0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_xor_mapped(&buf[..n], &txid)
}

fn parse_xor_mapped(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 || buf[0..2] != 0x0101u16.to_be_bytes() {
        return None;
    }
    if buf[8..20] != *txid {
        return None;
    }
    let mut i = 20usize;
    while i + 4 <= buf.len() {
        let atype = u16::from_be_bytes(buf[i..i + 2].try_into().ok()?);
        let alen = u16::from_be_bytes(buf[i + 2..i + 4].try_into().ok()?) as usize;
        let start = i + 4;
        let end = start.checked_add(alen)?;
        if end > buf.len() {
            return None;
        }
        if atype == 0x0020 && alen >= 8 && buf[start + 1] == 0x01 {
            let xport = u16::from_be_bytes(buf[start + 2..start + 4].try_into().ok()?);
            let port = xport ^ 0x2112;
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[start + 4..start + 8]);
            for (b, m) in ip.iter_mut().zip(0x2112A442u32.to_be_bytes()) {
                *b ^= m;
            }
            let addr = SocketAddr::from((Ipv4Addr::from(ip), port));
            if allowed_ip(addr.ip()) && addr.port() != 0 {
                return Some(addr);
            }
        }
        i = end + (4 - alen % 4) % 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_ipv4() {
        let txid = [3u8; 12];
        let mut buf = vec![0u8; 32];
        buf[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        buf[8..20].copy_from_slice(&txid);
        buf[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        buf[22..24].copy_from_slice(&8u16.to_be_bytes());
        buf[25] = 0x01;
        let port = 3478u16 ^ 0x2112;
        buf[26..28].copy_from_slice(&port.to_be_bytes());
        let ip = std::net::Ipv4Addr::new(203, 0, 113, 10);
        for (i, (b, m)) in ip.octets().iter().zip(0x2112A442u32.to_be_bytes()).enumerate() {
            buf[28 + i] = b ^ m;
        }
        let got = parse_xor_mapped(&buf, &txid).unwrap();
        assert_eq!(got, "203.0.113.10:3478".parse().unwrap());
    }
}
