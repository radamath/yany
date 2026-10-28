use crate::tls::acceptor_from_pem;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use yany_core::framing::{read_control, write_msg};
use yany_core::id::HostId;
use yany_core::protocol::{ControlMsg, Role};
use yany_core::rate_limit::RateLimiter;

struct HostSlot {
    join: mpsc::Sender<TlsStream<TcpStream>>,
}

struct State {
    hosts: HashMap<HostId, HostSlot>,
    register_limit: RateLimiter,
    connect_limit: RateLimiter,
}

impl State {
    fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            register_limit: RateLimiter::new(Duration::from_secs(60), 20).expect("limiter"),
            connect_limit: RateLimiter::new(Duration::from_secs(60), 40).expect("limiter"),
        }
    }
}

pub async fn run(bind: SocketAddr, cert: PathBuf, key: PathBuf) -> Result<()> {
    let acceptor = acceptor_from_pem(&cert, &key)?;
    let listener = TcpListener::bind(bind).await?;
    info!("yany-relay listening on {bind}");
    let state = Arc::new(Mutex::new(State::new()));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, peer, acceptor, state).await {
                warn!("peer {peer} closed: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<State>>,
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
        Role::Host => host_session(tls, peer, state).await,
        Role::Viewer => viewer_session(tls, peer, state).await,
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

async fn host_session(
    mut tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    {
        let mut g = state.lock().await;
        g.register_limit.check(&peer.ip().to_string())?;
        if g.hosts.len() >= 512 {
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
    let ControlMsg::RegisterHost { id } = msg else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "expected register".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let (tx, mut rx) = mpsc::channel::<TlsStream<TcpStream>>(1);
    {
        let mut g = state.lock().await;
        if g.hosts.contains_key(&id) {
            write_msg(
                &mut tls,
                &ControlMsg::Error {
                    message: "id in use".into(),
                },
            )
            .await?;
            return Ok(());
        }
        g.hosts.insert(id, HostSlot { join: tx });
    }
    write_msg(&mut tls, &ControlMsg::RegisterOk { id }).await?;
    info!("host {id} registered from {peer}");
    let viewer = tokio::time::timeout(Duration::from_secs(600), rx.recv()).await;
    {
        let mut g = state.lock().await;
        g.hosts.remove(&id);
    }
    let Ok(Some(mut viewer)) = viewer else {
        return Ok(());
    };
    write_msg(&mut tls, &ControlMsg::Incoming).await?;
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut viewer).await;
    Ok(())
}

async fn viewer_session(
    mut tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    {
        let mut g = state.lock().await;
        g.connect_limit.check(&peer.ip().to_string())?;
    }
    let msg = read_control(&mut tls).await?;
    let ControlMsg::Connect { target } = msg else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "expected connect".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let join = {
        let g = state.lock().await;
        g.hosts.get(&target).map(|h| h.join.clone())
    };
    let Some(join) = join else {
        write_msg(
            &mut tls,
            &ControlMsg::Error {
                message: "host not found".into(),
            },
        )
        .await?;
        return Ok(());
    };
    join.send(tls)
        .await
        .map_err(|_| anyhow::anyhow!("host busy or gone"))?;
    Ok(())
}
