use crate::config;
use crate::identity;
use crate::p2p::{self, Direct};
use crate::password;
use crate::session;
use crate::tls_client;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::split;
use tokio::sync::mpsc;
use yany_core::config::CaptureKind;
use yany_core::framing::{read_control, write_msg};
use yany_core::id::HostId;
use yany_core::join_token::sanitize_display_name;
use yany_core::protocol::{ControlMsg, PeerInfo, Role, PROTOCOL_VERSION};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Enroll {
    pub relay: String,
    pub token: String,
    pub name: String,
    pub fingerprint: String,
}

pub enum UiCmd {
    Enroll(Enroll),
    Connect {
        target: HostId,
        password: Option<String>,
    },
    Accept {
        session_id: [u8; 16],
    },
    Reject {
        session_id: [u8; 16],
    },
    Quit,
}

pub enum UiEvent {
    Status(String),
    Joined {
        id: HostId,
        token: String,
        valid_until: u64,
    },
    Token {
        token: String,
        valid_until: u64,
    },
    Fingerprint(String),
    Peers(Vec<PeerInfo>),
    Incoming {
        from: HostId,
        from_name: String,
        session_id: [u8; 16],
    },
    SessionEnded(String),
    Error(String),
    JoinRejected(String),
}

enum Once {
    Quit,
    Retry(String),
    JoinFail(String),
    Reenroll(Enroll),
}

pub async fn run(mut cmd_rx: mpsc::Receiver<UiCmd>, ui: std::sync::mpsc::Sender<UiEvent>) {
    let mut enroll: Option<Enroll> = None;
    loop {
        if enroll.is_none() {
            match cmd_rx.recv().await {
                Some(UiCmd::Enroll(e)) => enroll = Some(e),
                Some(UiCmd::Quit) | None => return,
                _ => continue,
            }
        }
        let Some(current) = enroll.clone() else {
            continue;
        };
        let _ = ui.send(UiEvent::Status(format!("relay {} bağlanıyor…", current.relay)));
        match run_once(&current, &mut cmd_rx, &ui).await {
            Once::Quit => return,
            Once::Reenroll(e) => enroll = Some(e),
            Once::JoinFail(msg) => {
                enroll = None;
                let _ = ui.send(UiEvent::JoinRejected(msg));
            }
            Once::Retry(msg) => {
                let _ = ui.send(UiEvent::Error(msg));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn run_once(
    enroll: &Enroll,
    cmd_rx: &mut mpsc::Receiver<UiCmd>,
    ui: &std::sync::mpsc::Sender<UiEvent>,
) -> Once {
    match run_control(enroll, cmd_rx, ui).await {
        Ok(once) => once,
        Err(e) => Once::Retry(e.to_string()),
    }
}

async fn run_control(
    enroll: &Enroll,
    cmd_rx: &mut mpsc::Receiver<UiCmd>,
    ui: &std::sync::mpsc::Sender<UiEvent>,
) -> Result<Once> {
    let dir = identity::data_dir();
    let id = identity::load_or_create_id(&dir.join("host.id"))?;
    let password_file = dir.join("host.password");
    let session_password = if password_file.exists() {
        password::load(&password_file)?
    } else {
        password::write_random(&password_file)?
    };
    let name = sanitize_display_name(&enroll.name).unwrap_or_else(|_| "yany-pc".into());
    let fp = if enroll.fingerprint.chars().filter(|c| c.is_ascii_hexdigit()).count() == 64 {
        Some(enroll.fingerprint.as_str())
    } else {
        None
    };
    let (tls, seen_fp) = tls_client::connect_tofu(&enroll.relay, fp).await?;
    let _ = ui.send(UiEvent::Fingerprint(seen_fp.clone()));
    let (mut reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Agent,
        },
    )
    .await?;
    write_msg(
        &mut writer,
        &ControlMsg::Join {
            token: enroll.token.clone(),
            name,
            id,
        },
    )
    .await?;
    let (join_token, until) = match read_control(&mut reader).await? {
        ControlMsg::JoinOk {
            id: got,
            token,
            valid_until_unix,
        } if got == id => (token, valid_until_unix),
        ControlMsg::JoinFail { message } => return Ok(Once::JoinFail(message)),
        ControlMsg::Error { message } => return Ok(Once::JoinFail(message)),
        other => bail!("unexpected join reply: {other:?}"),
    };
    let _ = ui.send(UiEvent::Joined {
        id,
        token: join_token.clone(),
        valid_until: until,
    });

    let (write_tx, mut write_rx) = mpsc::channel::<ControlMsg>(32);
    let write_task = tokio::spawn(async move {
        while let Some(msg) = write_rx.recv().await {
            if write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    let mut live_token = join_token;
    let mut outgoing_password: Option<String> = None;
    let mut pending_secrets: HashMap<[u8; 16], String> = HashMap::new();
    let mut p2p_inbox: HashMap<[u8; 16], mpsc::Sender<Vec<String>>> = HashMap::new();
    let busy = Arc::new(AtomicBool::new(false));
    let mut result = Once::Retry("control closed".into());

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(UiCmd::Quit) | None => {
                        result = Once::Quit;
                        break;
                    }
                    Some(UiCmd::Enroll(e)) => {
                        result = Once::Reenroll(e);
                        break;
                    }
                    Some(UiCmd::Connect { target, password }) => {
                        let unattended = password.is_some();
                        outgoing_password = password;
                        if write_tx.send(ControlMsg::ConnectRequest { target, unattended }).await.is_err() {
                            break;
                        }
                    }
                    Some(UiCmd::Accept { session_id }) => {
                        if write_tx.send(ControlMsg::Accept { session_id }).await.is_err() {
                            break;
                        }
                        let secret = pending_secrets
                            .remove(&session_id)
                            .unwrap_or_else(|| live_token.clone());
                        let (cand_tx, cand_rx) = mpsc::channel(1);
                        p2p_inbox.insert(session_id, cand_tx);
                        spawn_host_session(
                            enroll.relay.clone(),
                            seen_fp.clone(),
                            id,
                            session_id,
                            secret,
                            write_tx.clone(),
                            cand_rx,
                            busy.clone(),
                            ui.clone(),
                        );
                    }
                    Some(UiCmd::Reject { session_id }) => {
                        let _ = write_tx.send(ControlMsg::Reject {
                            session_id,
                            reason: "rejected".into(),
                        }).await;
                    }
                }
            }
            msg = read_control(&mut reader) => {
                match msg {
                    Ok(ControlMsg::PeerList { peers }) => {
                        let _ = ui.send(UiEvent::Peers(peers));
                    }
                    Ok(ControlMsg::TokenRotated { token, valid_until_unix }) => {
                        live_token = token.clone();
                        let _ = ui.send(UiEvent::Token { token, valid_until: valid_until_unix });
                    }
                    Ok(ControlMsg::IncomingCall { from, from_name, session_id, unattended, session_secret }) => {
                        pending_secrets.insert(session_id, session_secret);
                        if unattended {
                            if write_tx.send(ControlMsg::Accept { session_id }).await.is_err() {
                                break;
                            }
                            pending_secrets.remove(&session_id);
                            let (cand_tx, cand_rx) = mpsc::channel(1);
                            p2p_inbox.insert(session_id, cand_tx);
                            spawn_host_session(
                                enroll.relay.clone(),
                                seen_fp.clone(),
                                id,
                                session_id,
                                session_password.to_string(),
                                write_tx.clone(),
                                cand_rx,
                                busy.clone(),
                                ui.clone(),
                            );
                        } else {
                            let _ = ui.send(UiEvent::Incoming { from, from_name, session_id });
                        }
                    }
                    Ok(ControlMsg::SessionReady { session_id, session_secret }) => {
                        let secret = outgoing_password.take().unwrap_or(session_secret);
                        let (cand_tx, cand_rx) = mpsc::channel(1);
                        p2p_inbox.insert(session_id, cand_tx);
                        spawn_viewer_session(
                            enroll.relay.clone(),
                            seen_fp.clone(),
                            id,
                            session_id,
                            secret,
                            write_tx.clone(),
                            cand_rx,
                            busy.clone(),
                            ui.clone(),
                        );
                    }
                    Ok(ControlMsg::Candidates { session_id, addrs }) => {
                        if let Some(tx) = p2p_inbox.remove(&session_id) {
                            let _ = tx.send(addrs).await;
                        }
                    }
                    Ok(ControlMsg::Disconnect { reason }) => {
                        result = Once::Retry(reason);
                        break;
                    }
                    Ok(ControlMsg::Error { message }) => {
                        let _ = ui.send(UiEvent::Error(message));
                    }
                    Ok(other) => {
                        let _ = ui.send(UiEvent::Error(format!("beklenmeyen mesaj: {other:?}")));
                    }
                    Err(e) => {
                        result = Once::Retry(e.to_string());
                        break;
                    }
                }
            }
        }
    }
    write_task.abort();
    let _ = session_password;
    Ok(result)
}

fn spawn_host_session(
    relay: String,
    fingerprint: String,
    id: HostId,
    session_id: [u8; 16],
    secret: String,
    announce: mpsc::Sender<ControlMsg>,
    peer_rx: mpsc::Receiver<Vec<String>>,
    busy: Arc<AtomicBool>,
    ui: std::sync::mpsc::Sender<UiEvent>,
) {
    if busy.swap(true, Ordering::SeqCst) {
        let _ = ui.send(UiEvent::Error("oturum zaten açık".into()));
        return;
    }
    tokio::spawn(async move {
        let secret = Zeroizing::new(secret);
        let outcome =
            host_session(&relay, &fingerprint, id, session_id, &secret, announce, peer_rx).await;
        busy.store(false, Ordering::SeqCst);
        match outcome {
            Ok(()) => {
                let _ = ui.send(UiEvent::SessionEnded("oturum bitti".into()));
            }
            Err(e) => {
                let _ = ui.send(UiEvent::Error(e.to_string()));
            }
        }
    });
}

fn spawn_viewer_session(
    relay: String,
    fingerprint: String,
    id: HostId,
    session_id: [u8; 16],
    secret: String,
    announce: mpsc::Sender<ControlMsg>,
    peer_rx: mpsc::Receiver<Vec<String>>,
    busy: Arc<AtomicBool>,
    ui: std::sync::mpsc::Sender<UiEvent>,
) {
    if busy.swap(true, Ordering::SeqCst) {
        let _ = ui.send(UiEvent::Error("oturum zaten açık".into()));
        return;
    }
    tokio::spawn(async move {
        let secret = Zeroizing::new(secret);
        let outcome = viewer_session(
            &relay,
            &fingerprint,
            id,
            session_id,
            &secret,
            announce,
            peer_rx,
        )
        .await;
        busy.store(false, Ordering::SeqCst);
        match outcome {
            Ok(()) => {
                let _ = ui.send(UiEvent::SessionEnded("oturum bitti".into()));
            }
            Err(e) => {
                let _ = ui.send(UiEvent::Error(e.to_string()));
            }
        }
    });
}

async fn host_session(
    relay: &str,
    fingerprint: &str,
    id: HostId,
    session_id: [u8; 16],
    secret: &str,
    announce: mpsc::Sender<ControlMsg>,
    peer_rx: mpsc::Receiver<Vec<String>>,
) -> Result<()> {
    if let Some(direct) = p2p::try_direct(session_id, secret, announce, peer_rx).await {
        let direct_ok = match direct {
            Direct::Tcp(p) => {
                session::host_handshake_and_media(p.reader, p.writer, secret, CaptureKind::Dxgi)
                    .await
            }
            Direct::Udp(p) => {
                session::host_handshake_and_media_udp(p, secret, CaptureKind::Dxgi).await
            }
        };
        match direct_ok {
            Ok(()) => return Ok(()),
            Err(e) => tracing::warn!("direct tunnel failed, relay fallback: {e:#}"),
        }
    }
    let tls = tls_client::connect(relay, fingerprint).await?;
    let (reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Session,
        },
    )
    .await?;
    write_msg(
        &mut writer,
        &ControlMsg::SessionBind { session_id, id },
    )
    .await?;
    session::host_handshake_and_media(reader, writer, secret, CaptureKind::Dxgi).await
}

async fn viewer_session(
    relay: &str,
    fingerprint: &str,
    id: HostId,
    session_id: [u8; 16],
    secret: &str,
    announce: mpsc::Sender<ControlMsg>,
    peer_rx: mpsc::Receiver<Vec<String>>,
) -> Result<()> {
    if let Some(direct) = p2p::try_direct(session_id, secret, announce, peer_rx).await {
        let direct_ok = match direct {
            Direct::Tcp(p) => session::viewer_handshake_and_media(p.reader, p.writer, secret).await,
            Direct::Udp(p) => session::viewer_handshake_and_media_udp(p, secret).await,
        };
        match direct_ok {
            Ok(()) => return Ok(()),
            Err(e) => tracing::warn!("direct tunnel failed, relay fallback: {e:#}"),
        }
    }
    let tls = tls_client::connect(relay, fingerprint).await?;
    let (reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Session,
        },
    )
    .await?;
    write_msg(
        &mut writer,
        &ControlMsg::SessionBind { session_id, id },
    )
    .await?;
    session::viewer_handshake_and_media(reader, writer, secret).await
}

pub fn enroll_from_config(cfg: &config::ClientConfig) -> Result<Enroll> {
    Ok(Enroll {
        relay: config::normalize_relay(&cfg.relay)?,
        token: cfg.join_token.clone(),
        name: if cfg.display_name.trim().is_empty() {
            config::default_display_name()
        } else {
            sanitize_display_name(&cfg.display_name).unwrap_or_else(|_| "yany-pc".into())
        },
        fingerprint: cfg.fingerprint.clone(),
    })
}
