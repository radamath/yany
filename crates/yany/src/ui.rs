use crate::agent::{self, Enroll, UiCmd, UiEvent};
use crate::config::{self, ClientConfig};
use crate::identity;
use anyhow::Result;
use eframe::egui;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use yany_core::id::HostId;
use yany_core::join_token::parse_token;
use yany_core::protocol::PeerInfo;

pub fn run() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let handle = rt.handle().clone();
    let (ui_tx, ui_rx) = std::sync::mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    handle.spawn(agent::run(cmd_rx, ui_tx));

    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 520.0])
            .with_min_inner_size([520.0, 360.0]),
        ..Default::default()
    };
    let cmd = cmd_tx.clone();
    eframe::run_native(
        "Yany",
        native,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(YanyApp::new(handle, cmd, ui_rx)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = cmd_tx.blocking_send(UiCmd::Quit);
    Ok(())
}

struct Incoming {
    from: HostId,
    from_name: String,
    session_id: [u8; 16],
}

struct YanyApp {
    handle: tokio::runtime::Handle,
    cmd: mpsc::Sender<UiCmd>,
    ui_rx: std::sync::mpsc::Receiver<UiEvent>,
    setup: bool,
    relay: String,
    token_input: String,
    name: String,
    status: String,
    id: Option<HostId>,
    live_token: String,
    valid_until: u64,
    fingerprint: String,
    peers: Vec<PeerInfo>,
    selected: Option<HostId>,
    incoming: Option<Incoming>,
    session_password: String,
    cfg_path: std::path::PathBuf,
}

impl YanyApp {
    fn new(
        handle: tokio::runtime::Handle,
        cmd: mpsc::Sender<UiCmd>,
        ui_rx: std::sync::mpsc::Receiver<UiEvent>,
    ) -> Self {
        let cfg_path = config::config_path();
        let loaded = config::load(&cfg_path).ok().flatten();
        let mut app = Self {
            handle,
            cmd,
            ui_rx,
            setup: true,
            relay: String::new(),
            token_input: String::new(),
            name: config::default_display_name(),
            status: String::new(),
            id: identity::load_or_create_id(&identity::data_dir().join("host.id")).ok(),
            live_token: String::new(),
            valid_until: 0,
            fingerprint: String::new(),
            peers: Vec::new(),
            selected: None,
            incoming: None,
            session_password: String::new(),
            cfg_path,
        };
        if let Some(cfg) = loaded {
            app.relay = cfg.relay.clone();
            app.token_input = cfg.join_token.clone();
            app.live_token = cfg.join_token.clone();
            app.fingerprint = cfg.fingerprint.clone();
            if !cfg.display_name.trim().is_empty() {
                app.name = cfg.display_name.clone();
            }
            if let Ok(enroll) = agent::enroll_from_config(&cfg) {
                app.setup = false;
                app.status = "relay bağlanıyor…".into();
                app.send(UiCmd::Enroll(enroll));
            }
        }
        app
    }

    fn send(&self, cmd: UiCmd) {
        let tx = self.cmd.clone();
        self.handle.spawn(async move {
            let _ = tx.send(cmd).await;
        });
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.ui_rx.try_recv() {
            match ev {
                UiEvent::Status(s) => self.status = s,
                UiEvent::Joined {
                    id,
                    token,
                    valid_until,
                } => {
                    self.setup = false;
                    self.id = Some(id);
                    self.live_token = token;
                    self.valid_until = valid_until;
                    self.status = format!("bağlı — id {id}");
                    self.persist();
                }
                UiEvent::Token { token, valid_until } => {
                    self.live_token = token;
                    self.valid_until = valid_until;
                    self.persist();
                }
                UiEvent::Fingerprint(fp) => {
                    self.fingerprint = fp;
                    self.persist();
                }
                UiEvent::Peers(peers) => self.peers = peers,
                UiEvent::Incoming {
                    from,
                    from_name,
                    session_id,
                } => {
                    self.incoming = Some(Incoming {
                        from,
                        from_name,
                        session_id,
                    });
                }
                UiEvent::SessionEnded(s) | UiEvent::Error(s) => self.status = s,
                UiEvent::JoinRejected(s) => {
                    self.setup = true;
                    self.status = s;
                }
            }
        }
    }

    fn persist(&self) {
        let cfg = ClientConfig {
            relay: self.relay.clone(),
            fingerprint: self.fingerprint.clone(),
            join_token: self.live_token.clone(),
            display_name: self.name.clone(),
        };
        let _ = config::save(&self.cfg_path, &cfg);
    }

    fn connect_selected(&self, with_password: bool) {
        let Some(target) = self.selected else {
            return;
        };
        if self.id == Some(target) {
            return;
        }
        let password = if with_password {
            let p = self.session_password.trim();
            if p.len() < 8 {
                return;
            }
            Some(p.to_string())
        } else {
            None
        };
        self.send(UiCmd::Connect { target, password });
    }

    fn submit_setup(&mut self) {
        let relay = match config::normalize_relay(&self.relay) {
            Ok(r) => r,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        if parse_token(&self.token_input).is_err() {
            self.status = "kayıt şifresi 32 hex olmalı (tire olabilir)".into();
            return;
        }
        self.relay = relay.clone();
        self.live_token = self.token_input.clone();
        let enroll = Enroll {
            relay,
            token: self.token_input.clone(),
            name: self.name.clone(),
            fingerprint: self.fingerprint.clone(),
        };
        self.status = "relay bağlanıyor…".into();
        self.send(UiCmd::Enroll(enroll));
    }
}

impl eframe::App for YanyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        ctx.request_repaint_after(Duration::from_millis(250));

        if self.setup {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Yany kurulumu");
                ui.add_space(8.0);
                ui.label("Relay adresi (IP veya host; port yoksa 443)");
                ui.text_edit_singleline(&mut self.relay);
                ui.add_space(6.0);
                ui.label("Kayıt şifresi (SSH: docker exec yany-yany-relay-1 yany-token)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.token_input)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);
                ui.label("Görünen ad");
                ui.text_edit_singleline(&mut self.name);
                ui.add_space(12.0);
                if ui.button("Bağlan").clicked() {
                    self.submit_setup();
                }
                if !self.status.is_empty() {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::LIGHT_RED, &self.status);
                }
            });
            return;
        }

        let incoming = self.incoming.as_ref().map(|inc| {
            (inc.from, inc.from_name.clone(), inc.session_id)
        });
        if let Some((from, name, sid)) = incoming {
            let mut accept = false;
            let mut reject = false;
            egui::Window::new("Bağlantı isteği")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!("{name} ({from}) ekranı paylaşmanı istiyor."));
                    ui.horizontal(|ui| {
                        accept = ui.button("Kabul").clicked();
                        reject = ui.button("Reddet").clicked();
                    });
                });
            if accept {
                self.send(UiCmd::Accept { session_id: sid });
                self.incoming = None;
            } else if reject {
                self.send(UiCmd::Reject { session_id: sid });
                self.incoming = None;
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Yany");
                ui.separator();
                if let Some(id) = self.id {
                    ui.monospace(format!("ID {id}"));
                }
                ui.label(&self.name);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&self.status);
                });
            });
            ui.horizontal(|ui| {
                ui.label("Kayıt şifresi");
                ui.monospace(&self.live_token);
                if ui.small_button("Kopyala").clicked() {
                    ctx.copy_text(self.live_token.clone());
                }
                let left = self.valid_until.saturating_sub(unix_now());
                ui.label(format!("yenileme {}:{:02}", left / 60, left % 60));
            });
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Oturum şifresi (opsiyonel)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.session_password)
                        .password(true)
                        .desired_width(180.0),
                );
                if ui.button("Şifreyle bağlan").clicked() {
                    self.connect_selected(true);
                }
                ui.label("Çift tık: istek gönder");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.label("Adres defteri");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                let mut clicked = None;
                let mut doubled = None;
                for peer in &self.peers {
                    if self.id == Some(peer.id) {
                        ui.weak(format!("{}   {}   (bu cihaz)", peer.id, peer.name));
                        continue;
                    }
                    let selected = self.selected == Some(peer.id);
                    let resp = ui.selectable_label(selected, format!("{}   {}", peer.id, peer.name));
                    if resp.clicked() {
                        clicked = Some(peer.id);
                    }
                    if resp.double_clicked() {
                        doubled = Some(peer.id);
                    }
                }
                if let Some(id) = clicked {
                    self.selected = Some(id);
                }
                if let Some(id) = doubled {
                    self.selected = Some(id);
                    self.connect_selected(false);
                }
                if self.peers.len() <= 1 {
                    ui.weak("Aynı relay'e kayıtlı başka istemci yok.");
                }
            });
        });
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
