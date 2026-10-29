use crate::tls::acceptor_from_pem;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use yany_core::auth::random_bytes;
use yany_core::framing::{read_control, write_msg};
use yany_core::id::HostId;
use yany_core::join_token::{sanitize_display_name, JoinSecret, JOIN_TOKEN_TTL};
use yany_core::protocol::{ControlMsg, PeerInfo, Role};
use yany_core::rate_limit::RateLimiter;

struct AgentSlot {
    name: String,
    tx: mpsc::Sender<ControlMsg>,
}

struct PendingSession {
    viewer_id: HostId,
    host_id: HostId,
    accepted: bool,
    session_secret: String,
    viewer: Option<TlsStream<TcpStream>>,
    host: Option<TlsStream<TcpStream>>,
    notify: Arc<Notify>,
    created: Instant,
}

struct State {
    agents: HashMap<HostId, AgentSlot>,
    sessions: HashMap<[u8; 16], PendingSession>,
    connect_limit: RateLimiter,
    join_limit: RateLimiter,
}

impl State {
    fn new() -> Self {
        Self {
            agents: HashMap::new(),
            sessions: HashMap::new(),
            connect_limit: RateLimiter::new(Duration::from_secs(60), 40).expect("limiter"),
            join_limit: RateLimiter::new(Duration::from_secs(60), 10).expect("limiter"),
        }
    }
}

pub async fn run(bind: SocketAddr, cert: PathBuf, key: PathBuf, token_file: PathBuf) -> Result<()> {
    let acceptor = acceptor_from_pem(&cert, &key)?;
    let listener = TcpListener::bind(bind).await?;
    let secret = JoinSecret::load_or_create(&token_file, JOIN_TOKEN_TTL)?;
    info!(
        "yany-relay listening on {bind}; join token file {}",
        token_file.display()
    );
    let (token_tx, token_rx) = watch::channel(secret);
    let state = Arc::new(Mutex::new(State::new()));
    tokio::spawn(rotate_loop(token_file, token_tx.clone()));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        let token_rx = token_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, peer, acceptor, state, token_rx).await {
                warn!("peer {peer} closed: {e:#}");
            }
        });
    }
}

async fn rotate_loop(token_file: PathBuf, token_tx: watch::Sender<JoinSecret>) {
    loop {
        let wait = {
            let current = token_tx.borrow();
            let left = current.remaining();
            if left.is_zero() {
                Duration::from_secs(1)
            } else {
                left
            }
        };
        tokio::time::sleep(wait).await;
        let next = JoinSecret::generate(JOIN_TOKEN_TTL);
        if let Err(e) = next.write_file(&token_file) {
            warn!("join token persist failed: {e}");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        if token_tx.send(next).is_err() {
            break;
        }
        info!("join token rotated");
    }
}

async fn handle_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<State>>,
    token_rx: watch::Receiver<JoinSecret>,
) -> Result<()> {
    tcp.set_nodelay(true)?;
    let mut tls = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp))
        .await
        .map_err(|_| anyhow::anyhow!("tls handshake timeout"))??;
    let hello = read_control(&mut tls).await?;
    let ControlMsg::Hello { version: _, role } = hello else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "expected hello".into(),
            },
        )
        .await?;
        return Ok(());
    };
    match role {
        Role::Host | Role::Viewer => {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "legacy host/view disabled; use the Yany app".into(),
                },
            )
            .await?;
            Ok(())
        }
        Role::Agent => agent_session(tls, peer, state, token_rx).await,
        Role::Session => session_bind(tls, peer, state).await,
        Role::RelayAdmin => {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "unsupported role".into(),
                },
            )
            .await?;
            Ok(())
        }
    }
}

async fn agent_session(
    mut tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
    mut token_rx: watch::Receiver<JoinSecret>,
) -> Result<()> {
    {
        let mut g = state.lock().await;
        g.join_limit.check(&peer.ip().to_string())?;
        if g.agents.len() >= 512 {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "registry full".into(),
                },
            )
            .await?;
            return Ok(());
        }
    }
    let msg = read_control(&mut tls).await?;
    let ControlMsg::Join { token, name, id } = msg else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "expected join".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let name = match sanitize_display_name(&name) {
        Ok(n) => n,
        Err(_) => {
            write_msg(
                &mut tls,
                &ControlMsg::JoinFail {
                    message: "invalid name".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !id.is_valid() {
        write_msg(
            &mut tls,
            &ControlMsg::JoinFail {
                message: "invalid id".into(),
            },
        )
        .await?;
        return Ok(());
    }
    let matched = {
        let current = token_rx.borrow();
        if current.accepts_join(&token) {
            Some((current.display().to_string(), current.valid_until_unix()))
        } else {
            None
        }
    };
    let Some((token_display, until)) = matched else {
        tokio::time::sleep(Duration::from_millis(200)).await;
        write_msg(
            &mut tls,
            &ControlMsg::JoinFail {
                message: "invalid join token".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let (out_tx, mut out_rx) = mpsc::channel::<ControlMsg>(32);
    {
        let mut g = state.lock().await;
        if let Some(old) = g.agents.remove(&id) {
            let _ = old.tx.try_send(ControlMsg::Disconnect {
                reason: "replaced by new session".into(),
            });
        }
        g.agents.insert(
            id,
            AgentSlot {
                name: name.clone(),
                tx: out_tx.clone(),
            },
        );
    }
    write_msg(
        &mut tls,
        &ControlMsg::JoinOk {
            id,
            token: token_display,
            valid_until_unix: until,
        },
    )
    .await?;
    info!("agent {id} joined from {peer}");
    broadcast_peers(&state).await;

    let (mut reader, mut writer) = tokio::io::split(tls);
    let write_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    let result = agent_read_loop(id, &mut reader, &state, &mut token_rx, &out_tx).await;
    write_task.abort();
    {
        let mut g = state.lock().await;
        if g.agents
            .get(&id)
            .map(|a| a.tx.same_channel(&out_tx))
            .unwrap_or(false)
        {
            g.agents.remove(&id);
        }
        g.sessions.retain(|_, s| {
            s.viewer_id != id && s.host_id != id
        });
    }
    broadcast_peers(&state).await;
    result
}

async fn agent_read_loop<R: tokio::io::AsyncReadExt + Unpin>(
    me: HostId,
    reader: &mut R,
    state: &Arc<Mutex<State>>,
    token_rx: &mut watch::Receiver<JoinSecret>,
    out_tx: &mpsc::Sender<ControlMsg>,
) -> Result<()> {
    loop {
        tokio::select! {
            msg = read_control(reader) => {
                match msg? {
                    ControlMsg::ConnectRequest { target, unattended } => {
                        start_call(me, target, unattended, state).await?;
                    }
                    ControlMsg::Accept { session_id } => {
                        accept_call(me, session_id, state).await?;
                    }
                    ControlMsg::Reject { session_id, reason } => {
                        reject_call(me, session_id, reason, state).await?;
                    }
                    ControlMsg::Disconnect { .. } => break,
                    ControlMsg::Error { .. } => break,
                    other => {
                        let _ = out_tx.send(ControlMsg::Error {
                            message: format!("unexpected {other:?}"),
                        }).await;
                    }
                }
            }
            changed = token_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let (token, until) = {
                    let g = token_rx.borrow();
                    (g.display().to_string(), g.valid_until_unix())
                };
                out_tx.send(ControlMsg::TokenRotated {
                    token,
                    valid_until_unix: until,
                }).await?;
            }
        }
    }
    Ok(())
}

async fn start_call(
    from: HostId,
    target: HostId,
    unattended: bool,
    state: &Arc<Mutex<State>>,
) -> Result<()> {
    if from == target {
        send_to(state, from, ControlMsg::Error { message: "cannot connect to self".into() }).await;
        return Ok(());
    }
    let session_id = random_bytes::<16>();
    let session_secret: String = random_bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let from_name;
    let host_tx;
    {
        let mut g = state.lock().await;
        g.sessions.retain(|_, s| s.created.elapsed() < Duration::from_secs(60));
        if g.sessions.len() >= 256 {
            drop(g);
            send_to(state, from, ControlMsg::Error { message: "too many sessions".into() }).await;
            return Ok(());
        }
        let Some(host) = g.agents.get(&target) else {
            drop(g);
            send_to(state, from, ControlMsg::Error { message: "peer not found".into() }).await;
            return Ok(());
        };
        host_tx = host.tx.clone();
        from_name = g
            .agents
            .get(&from)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "unknown".into());
        g.sessions.insert(
            session_id,
            PendingSession {
                viewer_id: from,
                host_id: target,
                accepted: false,
                session_secret: session_secret.clone(),
                viewer: None,
                host: None,
                notify: Arc::new(Notify::new()),
                created: Instant::now(),
            },
        );
    }
    let _ = host_tx
        .send(ControlMsg::IncomingCall {
            from,
            from_name,
            session_id,
            unattended,
            session_secret,
        })
        .await;
    Ok(())
}

async fn accept_call(host_id: HostId, session_id: [u8; 16], state: &Arc<Mutex<State>>) -> Result<()> {
    let (viewer_tx, session_secret) = {
        let mut g = state.lock().await;
        let (viewer_id, session_secret) = {
            let Some(pending) = g.sessions.get_mut(&session_id) else {
                return Ok(());
            };
            if pending.host_id != host_id {
                return Ok(());
            }
            pending.accepted = true;
            (pending.viewer_id, pending.session_secret.clone())
        };
        (
            g.agents.get(&viewer_id).map(|a| a.tx.clone()),
            session_secret,
        )
    };
    if let Some(tx) = viewer_tx {
        let _ = tx
            .send(ControlMsg::SessionReady {
                session_id,
                session_secret,
            })
            .await;
    }
    Ok(())
}

async fn reject_call(
    host_id: HostId,
    session_id: [u8; 16],
    reason: String,
    state: &Arc<Mutex<State>>,
) -> Result<()> {
    let reason = if reason.len() > 256 {
        "rejected".into()
    } else {
        reason
    };
    let viewer_tx = {
        let mut g = state.lock().await;
        let Some(pending) = g.sessions.remove(&session_id) else {
            return Ok(());
        };
        if pending.host_id != host_id {
            g.sessions.insert(session_id, pending);
            return Ok(());
        }
        g.agents.get(&pending.viewer_id).map(|a| a.tx.clone())
    };
    if let Some(tx) = viewer_tx {
        let _ = tx
            .send(ControlMsg::Error {
                message: if reason.is_empty() {
                    "rejected".into()
                } else {
                    reason
                },
            })
            .await;
    }
    Ok(())
}

async fn session_bind(
    mut tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    {
        let mut g = state.lock().await;
        g.connect_limit.check(&peer.ip().to_string())?;
    }
    let msg = read_control(&mut tls).await?;
    let ControlMsg::SessionBind { session_id, id } = msg else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "expected session bind".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let notify = {
        let mut g = state.lock().await;
        let Some(pending) = g.sessions.get_mut(&session_id) else {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "unknown session".into(),
                },
            )
            .await?;
            return Ok(());
        };
        if !pending.accepted {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "session not accepted".into(),
                },
            )
            .await?;
            return Ok(());
        }
        if pending.created.elapsed() > Duration::from_secs(60) {
            g.sessions.remove(&session_id);
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "session expired".into(),
                },
            )
            .await?;
            return Ok(());
        }
        if id == pending.viewer_id {
            if pending.viewer.is_some() {
                write_msg(
                    &mut tls,
                    &ControlMsg::Error {
                        message: "already bound".into(),
                    },
                )
                .await?;
                return Ok(());
            }
            pending.viewer = Some(tls);
        } else if id == pending.host_id {
            if pending.host.is_some() {
                write_msg(
                    &mut tls,
                    &ControlMsg::Error {
                        message: "already bound".into(),
                    },
                )
                .await?;
                return Ok(());
            }
            pending.host = Some(tls);
        } else {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "session id mismatch".into(),
                },
            )
            .await?;
            return Ok(());
        }
        let n = pending.notify.clone();
        n.notify_waiters();
        n
    };

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let pair = {
            let mut g = state.lock().await;
            let ready = g
                .sessions
                .get(&session_id)
                .map(|s| s.viewer.is_some() && s.host.is_some())
                .unwrap_or(false);
            if ready {
                g.sessions.remove(&session_id).and_then(|mut s| {
                    Some((s.host.take()?, s.viewer.take()?))
                })
            } else if !g.sessions.contains_key(&session_id) {
                None
            } else {
                drop(g);
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    let mut g = state.lock().await;
                    g.sessions.remove(&session_id);
                    return Ok(());
                }
                tokio::time::timeout(left, notify.notified()).await.ok();
                continue;
            }
        };
        if let Some((mut host, mut viewer)) = pair {
            let _ = tokio::io::copy_bidirectional(&mut host, &mut viewer).await;
        }
        return Ok(());
    }
}

async fn broadcast_peers(state: &Arc<Mutex<State>>) {
    let (peers, txs) = {
        let g = state.lock().await;
        let mut peers: Vec<PeerInfo> = g
            .agents
            .iter()
            .map(|(id, a)| PeerInfo {
                id: *id,
                name: a.name.clone(),
            })
            .collect();
        peers.sort_by_key(|p| p.id.raw());
        let txs: Vec<_> = g.agents.values().map(|a| a.tx.clone()).collect();
        (peers, txs)
    };
    let msg = ControlMsg::PeerList { peers };
    for tx in txs {
        let _ = tx.send(msg.clone()).await;
    }
}

async fn send_to(state: &Arc<Mutex<State>>, id: HostId, msg: ControlMsg) {
    let tx = {
        let g = state.lock().await;
        g.agents.get(&id).map(|a| a.tx.clone())
    };
    if let Some(tx) = tx {
        let _ = tx.send(msg).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_list_sorted_by_id() {
        let mut agents = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        agents.insert(
            HostId::from_raw(222222222).unwrap(),
            AgentSlot {
                name: "b".into(),
                tx: tx.clone(),
            },
        );
        agents.insert(
            HostId::from_raw(111111111).unwrap(),
            AgentSlot {
                name: "a".into(),
                tx,
            },
        );
        let mut peers: Vec<PeerInfo> = agents
            .iter()
            .map(|(id, a)| PeerInfo {
                id: *id,
                name: a.name.clone(),
            })
            .collect();
        peers.sort_by_key(|p| p.id.raw());
        assert_eq!(peers[0].name, "a");
        assert_eq!(peers[1].name, "b");
    }
}
