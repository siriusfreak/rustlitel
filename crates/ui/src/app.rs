//! The rustlitel egui application: auth, agent list, terminal, exec, installer
//! links, downloads, self-delete, and the theme switch. Styled to match the
//! approved design mockup.

use std::sync::{Arc, Mutex};

use egui::{vec2, Align, Color32, FontId, Layout, Margin, Rect, RichText, Rounding, Sense, Stroke};
use serde::Deserialize;

use crate::term::Terminal;
use crate::theme::{self, Palette, ThemePref};

// --- JSON shapes the relay returns -----------------------------------------

#[derive(Deserialize, Clone)]
struct AgentInfo {
    agent_id: String,
    name: String,
    os: String,
    shells: Vec<String>,
    allow_remote: bool,
    connected_secs: u64,
}

#[derive(Deserialize)]
struct Me {
    authenticated: bool,
    username: Option<String>,
    oidc: bool,
}

#[derive(Deserialize)]
struct ExecResp {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    truncated: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
struct InstallerLink {
    url: String,
    expires_days: u64,
}

// --- async plumbing ---------------------------------------------------------

enum Msg {
    Me(Result<Me, String>),
    LoginOk,
    LoginErr(String),
    Agents(Result<Vec<AgentInfo>, String>),
    Exec(Result<ExecResp, String>),
    Installer(Result<InstallerLink, String>),
    Uninstalled(Result<(), String>),
}

type Inbox = Arc<Mutex<Vec<Msg>>>;

enum Auth {
    Unknown,
    Anon,
    Authed { username: Option<String> },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CentralTab {
    Terminal,
    Exec,
}

pub struct RustlitelApp {
    http_origin: String,
    ws_origin: String,

    theme: ThemePref,
    applied_dark: Option<bool>,

    inbox: Inbox,
    auth: Auth,
    oidc_enabled: bool,

    login_token: String,
    login_busy: bool,
    login_error: Option<String>,

    agents: Vec<AgentInfo>,
    agents_error: Option<String>,
    agents_loading: bool,
    last_agents_fetch: f64,
    selected: Option<String>,

    tab: CentralTab,
    term: Option<Terminal>,
    term_shell: String,

    exec_cmd: String,
    exec_shell: String,
    exec_timeout: String,
    exec_busy: bool,
    exec_result: Option<Result<ExecResp, String>>,

    inst_os: String,
    inst_name: String,
    inst_busy: bool,
    inst_link: Option<InstallerLink>,
    inst_error: Option<String>,

    confirm_uninstall: Option<String>,
    note: Option<String>,
}

impl RustlitelApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install_fonts(&cc.egui_ctx);
        let theme = cc
            .storage
            .and_then(|s| eframe::get_value::<ThemePref>(s, "theme"))
            .unwrap_or_default();
        let (http_origin, ws_origin) = origins();
        Self {
            http_origin,
            ws_origin,
            theme,
            applied_dark: None,
            inbox: Arc::new(Mutex::new(Vec::new())),
            auth: Auth::Unknown,
            oidc_enabled: false,
            login_token: String::new(),
            login_busy: false,
            login_error: None,
            agents: Vec::new(),
            agents_error: None,
            agents_loading: false,
            last_agents_fetch: 0.0,
            selected: None,
            tab: CentralTab::Terminal,
            term: None,
            term_shell: String::new(),
            exec_cmd: String::new(),
            exec_shell: String::new(),
            exec_timeout: String::new(),
            exec_busy: false,
            exec_result: None,
            inst_os: "windows".to_string(),
            inst_name: String::new(),
            inst_busy: false,
            inst_link: None,
            inst_error: None,
            confirm_uninstall: None,
            note: None,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.http_origin, path)
    }

    // --- requests ---

    fn fetch_me(&mut self, ctx: &egui::Context) {
        let req = ehttp::Request::get(self.url("/api/me"));
        spawn_json(&self.inbox, ctx, req, Msg::Me);
    }

    fn do_login(&mut self, ctx: &egui::Context) {
        self.login_busy = true;
        self.login_error = None;
        let body = serde_json::json!({ "token": self.login_token }).to_string();
        let req = json_post(self.url("/api/login"), body);
        let inbox = self.inbox.clone();
        let ctx2 = ctx.clone();
        ehttp::fetch(req, move |res| {
            let msg = match res {
                Ok(r) if r.ok => Msg::LoginOk,
                Ok(r) if r.status == 401 => Msg::LoginErr("That token wasn't accepted.".to_string()),
                Ok(r) => Msg::LoginErr(format!("Login failed (HTTP {}).", r.status)),
                Err(e) => Msg::LoginErr(e),
            };
            inbox.lock().unwrap().push(msg);
            ctx2.request_repaint();
        });
    }

    fn fetch_agents(&mut self, ctx: &egui::Context) {
        self.agents_loading = true;
        let req = ehttp::Request::get(self.url("/api/agents"));
        spawn_json(&self.inbox, ctx, req, Msg::Agents);
    }

    fn do_exec(&mut self, ctx: &egui::Context, agent: &str) {
        self.exec_busy = true;
        self.exec_result = None;
        let mut body = serde_json::Map::new();
        body.insert("agent".into(), agent.into());
        body.insert("command".into(), self.exec_cmd.clone().into());
        if !self.exec_shell.trim().is_empty() {
            body.insert("shell".into(), self.exec_shell.trim().into());
        }
        if let Ok(secs) = self.exec_timeout.trim().parse::<u64>() {
            body.insert("timeout_secs".into(), secs.into());
        }
        let req = json_post(self.url("/api/exec"), serde_json::Value::Object(body).to_string());
        spawn_json(&self.inbox, ctx, req, Msg::Exec);
    }

    fn do_installer(&mut self, ctx: &egui::Context) {
        self.inst_busy = true;
        self.inst_error = None;
        let mut body = serde_json::Map::new();
        body.insert("os".into(), self.inst_os.clone().into());
        if !self.inst_name.trim().is_empty() {
            body.insert("name".into(), self.inst_name.trim().into());
        }
        let req = json_post(
            self.url("/api/installer"),
            serde_json::Value::Object(body).to_string(),
        );
        spawn_json(&self.inbox, ctx, req, Msg::Installer);
    }

    fn do_uninstall(&mut self, ctx: &egui::Context, agent: &str) {
        let body = serde_json::json!({ "agent": agent }).to_string();
        let req = json_post(self.url("/api/uninstall"), body);
        let inbox = self.inbox.clone();
        let ctx2 = ctx.clone();
        ehttp::fetch(req, move |res| {
            let msg = match res {
                Ok(r) if r.ok => Msg::Uninstalled(Ok(())),
                Ok(r) => Msg::Uninstalled(Err(format!("HTTP {}", r.status))),
                Err(e) => Msg::Uninstalled(Err(e)),
            };
            inbox.lock().unwrap().push(msg);
            ctx2.request_repaint();
        });
    }

    fn do_logout(&mut self, ctx: &egui::Context) {
        if self.oidc_enabled {
            navigate(&self.url("/oauth2/logout"));
            return;
        }
        let req = json_post(self.url("/api/logout"), "{}".to_string());
        ehttp::fetch(req, |_| {});
        self.auth = Auth::Anon;
        self.reset_session_state();
        ctx.request_repaint();
    }

    fn reset_session_state(&mut self) {
        self.agents.clear();
        self.selected = None;
        self.term = None;
        self.exec_result = None;
        self.inst_link = None;
    }

    // --- inbox ---

    fn drain(&mut self, ctx: &egui::Context) {
        let msgs: Vec<Msg> = std::mem::take(&mut *self.inbox.lock().unwrap());
        for m in msgs {
            match m {
                Msg::Me(Ok(me)) => {
                    self.oidc_enabled = me.oidc;
                    if me.authenticated {
                        self.auth = Auth::Authed {
                            username: me.username,
                        };
                        self.fetch_agents(ctx);
                    } else {
                        self.auth = Auth::Anon;
                    }
                }
                Msg::Me(Err(_)) => self.auth = Auth::Anon,
                Msg::LoginOk => {
                    self.login_busy = false;
                    self.login_token.clear();
                    self.fetch_me(ctx);
                }
                Msg::LoginErr(e) => {
                    self.login_busy = false;
                    self.login_error = Some(e);
                }
                Msg::Agents(Ok(list)) => {
                    self.agents_loading = false;
                    self.agents_error = None;
                    self.agents = list;
                }
                Msg::Agents(Err(e)) => {
                    self.agents_loading = false;
                    self.agents_error = Some(e);
                }
                Msg::Exec(res) => {
                    self.exec_busy = false;
                    self.exec_result = Some(res);
                }
                Msg::Installer(Ok(link)) => {
                    self.inst_busy = false;
                    self.inst_link = Some(link);
                }
                Msg::Installer(Err(e)) => {
                    self.inst_busy = false;
                    self.inst_error = Some(e);
                }
                Msg::Uninstalled(Ok(())) => {
                    self.note = Some("Uninstall requested — the agent will drop off shortly.".into());
                }
                Msg::Uninstalled(Err(e)) => {
                    self.note = Some(format!("Uninstall failed: {e}"));
                }
            }
        }
    }

    fn ensure_theme(&mut self, ctx: &egui::Context) {
        let dark = self.theme.is_dark();
        if self.applied_dark != Some(dark) {
            self.theme.apply(ctx);
            self.applied_dark = Some(dark);
        }
    }

    // --- shared widgets ---

    fn theme_segmented(&mut self, ui: &mut egui::Ui, reversed: bool) {
        let p = theme::current(ui.ctx());
        // A right-aligned (right_to_left) parent flips the visual order, so the
        // header pre-reverses to keep the on-screen reading System · Light · Dark.
        let order = if reversed {
            [ThemePref::Dark, ThemePref::Light, ThemePref::System]
        } else {
            ThemePref::ALL
        };
        egui::Frame::none()
            .stroke(Stroke::new(0.5_f32,p.border))
            .rounding(6.0)
            .inner_margin(Margin::same(1.0))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.horizontal(|ui| {
                    for t in order {
                        let on = self.theme == t;
                        let txt = RichText::new(t.label())
                            .size(12.0)
                            .color(if on { p.accent } else { p.text_secondary });
                        let btn = egui::Button::new(txt)
                            .fill(if on { p.accent_muted } else { Color32::TRANSPARENT })
                            .stroke(Stroke::NONE)
                            .rounding(5.0)
                            .min_size(vec2(46.0, 20.0));
                        if ui.add(btn).clicked() {
                            self.theme = t;
                        }
                    }
                });
            });
    }

    // --- login ---

    fn ui_login(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.18);
                let (rect, _) = ui.allocate_exact_size(vec2(44.0, 44.0), Sense::hover());
                ui.painter().rect_filled(rect, Rounding::same(12.0), p.accent);
                ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, ">_", FontId::monospace(22.0), Color32::WHITE);
                ui.add_space(8.0);
                ui.label(RichText::new("rustlitel").size(24.0).strong().color(p.text));
                ui.add_space(2.0);
                ui.label(RichText::new("remote shell relay").size(13.0).color(p.text_muted));
                ui.add_space(20.0);

                egui::Frame::none()
                    .fill(p.card)
                    .stroke(Stroke::new(0.5_f32,p.border))
                    .rounding(12.0)
                    .inner_margin(Margin::same(20.0))
                    .show(ui, |ui| {
                        ui.set_width(320.0);
                        ui.vertical_centered_justified(|ui| {
                            // With Keycloak configured, that's the only web
                            // login — the operator token stays a CLI/script
                            // credential (Bearer), not shown here.
                            if self.oidc_enabled {
                                let b = egui::Button::new(
                                    RichText::new("Sign in with Keycloak").color(Color32::WHITE),
                                )
                                .fill(p.accent)
                                .min_size(vec2(0.0, 36.0));
                                if ui.add(b).clicked() {
                                    navigate(&self.url("/oauth2/login?rd=/"));
                                }
                                return;
                            }

                            ui.with_layout(Layout::left_to_right(Align::Min), |ui| {
                                ui.label(RichText::new("Operator token").size(13.0).color(p.text_secondary));
                            });
                            ui.add_space(6.0);
                            let field = ui.add(
                                egui::TextEdit::singleline(&mut self.login_token)
                                    .password(true)
                                    .hint_text("paste operator token")
                                    .margin(Margin::symmetric(10.0, 7.0))
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(8.0);
                            let submit = (field.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                                || ui
                                    .add(
                                        egui::Button::new(RichText::new("Log in").color(Color32::WHITE))
                                            .fill(p.accent)
                                            .min_size(vec2(0.0, 32.0)),
                                    )
                                    .clicked();
                            if submit && !self.login_busy && !self.login_token.is_empty() {
                                self.do_login(ctx);
                            }
                            if self.login_busy {
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label(RichText::new("signing in…").color(p.text_secondary));
                                });
                            }
                            if let Some(err) = &self.login_error {
                                ui.add_space(8.0);
                                ui.label(RichText::new(err).size(13.0).color(p.danger));
                            }
                        });
                    });

                ui.add_space(16.0);
                ui.allocate_ui_with_layout(vec2(160.0, 26.0), Layout::top_down(Align::Center), |ui| {
                    self.theme_segmented(ui, false);
                });
            });
        });
    }

    // --- header ---

    fn ui_header(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::none()
                    .fill(p.card)
                    .inner_margin(Margin::symmetric(14.0, 8.0))
                    .stroke(Stroke::new(0.5_f32,p.border)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    wordmark(ui, &p, 16.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        // logout
                        if ui
                            .add(egui::Button::new(RichText::new("Log out").size(12.5).color(p.text_secondary)).fill(Color32::TRANSPARENT).stroke(Stroke::new(0.5_f32,p.border)))
                            .clicked()
                        {
                            self.do_logout(ctx);
                        }
                        ui.add_space(4.0);
                        if let Auth::Authed { username: Some(u), .. } = &self.auth {
                            user_chip(ui, &p, u);
                            ui.add_space(6.0);
                        }
                        self.theme_segmented(ui, true);
                    });
                });
            });
    }

    // --- sidebar ---

    fn ui_side(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::SidePanel::left("agents")
            .resizable(false)
            .exact_width(222.0)
            .frame(
                egui::Frame::none()
                    .fill(p.card)
                    .inner_margin(Margin::symmetric(10.0, 10.0))
                    .stroke(Stroke::new(0.5_f32,p.border)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Agents").size(13.0).strong().color(p.text_secondary));
                    ui.label(RichText::new(format!("· {}", self.agents.len())).size(13.0).color(p.text_muted));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Refresh").size(11.5).color(p.text_secondary)).fill(Color32::TRANSPARENT).stroke(Stroke::NONE))
                            .clicked()
                        {
                            self.fetch_agents(ctx);
                        }
                        if self.agents_loading {
                            ui.add(egui::Spinner::new().size(13.0));
                        }
                    });
                });
                ui.add_space(4.0);

                if let Some(err) = &self.agents_error {
                    ui.label(RichText::new(err).size(12.0).color(p.danger));
                }
                ui.separator();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.agents.is_empty() && !self.agents_loading {
                            ui.add_space(8.0);
                            ui.label(RichText::new("No agents connected.").size(12.5).color(p.text_muted));
                        }
                        let agents = self.agents.clone();
                        for a in &agents {
                            let selected = self.selected.as_deref() == Some(&a.agent_id);
                            if agent_row(ui, &p, a, selected).clicked() {
                                self.select_agent(&a.agent_id);
                            }
                        }
                        ui.add_space(8.0);
                        ui.separator();
                        self.ui_installer(ui, &p);
                        self.ui_downloads(ui, &p);
                    });
            });
    }

    fn select_agent(&mut self, id: &str) {
        if self.selected.as_deref() == Some(id) {
            return;
        }
        self.selected = Some(id.to_string());
        self.term = None;
        self.exec_result = None;
        if let Some(a) = self.agents.iter().find(|a| a.agent_id == id) {
            let first = a.shells.first().cloned().unwrap_or_default();
            self.term_shell = first.clone();
            self.exec_shell = first;
        }
    }

    fn ui_installer(&mut self, ui: &mut egui::Ui, p: &Palette) {
        egui::CollapsingHeader::new(RichText::new("Add an agent").size(13.0).color(p.text_secondary))
            .id_salt("add_agent")
            .show(ui, |ui| {
                ui.label(RichText::new("Generate a one-click installer link to open on the target machine.").size(12.0).color(p.text_muted));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("OS").size(12.5).color(p.text_secondary));
                    egui::ComboBox::from_id_salt("inst_os")
                        .selected_text(&self.inst_os)
                        .width(90.0)
                        .show_ui(ui, |ui| {
                            for os in ["windows", "macos", "linux"] {
                                ui.selectable_value(&mut self.inst_os, os.to_string(), os);
                            }
                        });
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.inst_name)
                        .hint_text("name (optional)")
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(4.0);
                let ctx = ui.ctx().clone();
                if accent_button(ui, p, "Generate link", !self.inst_busy).clicked() && !self.inst_busy {
                    self.do_installer(&ctx);
                }
                if self.inst_busy {
                    ui.add(egui::Spinner::new().size(14.0));
                }
                if let Some(err) = &self.inst_error {
                    ui.label(RichText::new(err).size(12.0).color(p.danger));
                }
                if let Some(link) = &self.inst_link {
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("valid {} days", link.expires_days)).size(11.5).color(p.text_muted));
                    let url = link.url.clone();
                    if ui.add(egui::Button::new(RichText::new("Copy link").size(12.5)).fill(Color32::TRANSPARENT).stroke(Stroke::new(0.5_f32,p.border_strong))).clicked() {
                        ui.ctx().copy_text(url.clone());
                    }
                    let mut shown = url.clone();
                    ui.add(egui::TextEdit::singleline(&mut shown).font(FontId::monospace(11.0)).desired_width(f32::INFINITY));
                }
            });
    }

    fn ui_downloads(&mut self, ui: &mut egui::Ui, p: &Palette) {
        egui::CollapsingHeader::new(RichText::new("Download agent").size(13.0).color(p.text_secondary))
            .id_salt("downloads")
            .show(ui, |ui| {
                for (label, file) in [
                    ("Windows (.exe)", "rustlitel-agent-windows.exe"),
                    ("macOS", "rustlitel-agent-macos"),
                    ("Linux", "rustlitel-agent-linux"),
                ] {
                    ui.hyperlink_to(RichText::new(label).size(12.5), self.url(&format!("/download/{file}")));
                }
            });
    }

    // --- central ---

    fn ui_central(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(p.page).inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| {
                let Some(agent_id) = self.selected.clone() else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.4);
                        ui.label(RichText::new("Select an agent on the left.").color(p.text_muted));
                    });
                    return;
                };
                let agent = self.agents.iter().find(|a| a.agent_id == agent_id).cloned();

                // header row
                ui.horizontal(|ui| {
                    ui.label(RichText::new(agent.as_ref().map(|a| a.name.clone()).unwrap_or_else(|| agent_id.clone())).size(16.0).strong().color(p.text));
                    if let Some(a) = &agent {
                        let shell = a.shells.first().cloned().unwrap_or_default();
                        ui.label(RichText::new(format!("{} · {}", short_os(&a.os), shell)).size(12.5).color(p.text_muted));
                        ui.add_space(2.0);
                        if a.allow_remote {
                            pill(ui, "remote on", p.success, mix(p.success, p.page, 0.82));
                        } else {
                            pill(ui, "remote off", p.text_muted, p.hover);
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Uninstall").size(12.5).color(p.danger)).fill(Color32::TRANSPARENT).stroke(Stroke::new(0.5_f32,p.danger)))
                            .on_hover_text("Tell the agent to remove itself from that machine")
                            .clicked()
                        {
                            self.confirm_uninstall = Some(agent_id.clone());
                        }
                    });
                });

                ui.add_space(10.0);

                // tabs + (when a terminal is open) status and disconnect
                let term_state = self.term.as_ref().map(|t| (t.open, t.closed, t.status.clone()));
                let mut disconnect = false;
                ui.horizontal(|ui| {
                    if tab(ui, &p, "Terminal", self.tab == CentralTab::Terminal).clicked() {
                        self.tab = CentralTab::Terminal;
                    }
                    ui.add_space(14.0);
                    if tab(ui, &p, "Exec", self.tab == CentralTab::Exec).clicked() {
                        self.tab = CentralTab::Exec;
                    }
                    if self.tab == CentralTab::Terminal {
                        if let Some((open, closed, status)) = &term_state {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add(egui::Button::new(RichText::new(if *closed { "Close" } else { "Disconnect" }).size(12.0).color(p.text_secondary)).fill(Color32::TRANSPARENT).stroke(Stroke::new(0.5_f32, p.border_strong)))
                                    .clicked()
                                {
                                    disconnect = true;
                                }
                                ui.add_space(8.0);
                                let (c, label) = if *closed {
                                    (p.text_muted, status.clone())
                                } else if *open {
                                    (p.success, "connected".to_string())
                                } else {
                                    (p.warning, "connecting…".to_string())
                                };
                                ui.label(RichText::new(label).size(12.0).color(c));
                                dot(ui, c, 7.0);
                            });
                        }
                    }
                });
                if disconnect {
                    self.term = None;
                }
                ui.add_space(3.0);
                ui.separator();
                ui.add_space(8.0);

                match self.tab {
                    CentralTab::Terminal => self.ui_terminal(ui, &p, &agent_id),
                    CentralTab::Exec => self.ui_exec(ui, &p, &agent_id),
                }
            });
    }

    fn ui_terminal(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str) {
        if self.term.is_none() {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let shells = self
                    .agents
                    .iter()
                    .find(|a| a.agent_id == agent_id)
                    .map(|a| a.shells.clone())
                    .unwrap_or_default();
                if !shells.is_empty() {
                    ui.label(RichText::new("shell").size(12.5).color(p.text_secondary));
                    egui::ComboBox::from_id_salt("term_shell")
                        .selected_text(if self.term_shell.is_empty() {
                            "default"
                        } else {
                            self.term_shell.as_str()
                        })
                        .show_ui(ui, |ui| {
                            for s in &shells {
                                ui.selectable_value(&mut self.term_shell, s.clone(), s);
                            }
                        });
                    ui.add_space(6.0);
                }
                if ui
                    .add(egui::Button::new(RichText::new("Open terminal").color(Color32::WHITE)).fill(p.accent).min_size(vec2(150.0, 32.0)))
                    .clicked()
                {
                    let shell = (!self.term_shell.is_empty()).then(|| self.term_shell.clone());
                    match Terminal::connect(&self.ws_origin, agent_id, shell.as_deref(), ui.ctx()) {
                        Ok(t) => self.term = Some(t),
                        Err(e) => self.note = Some(format!("Terminal error: {e}")),
                    }
                }
            });
            ui.add_space(6.0);
            ui.label(RichText::new("Opens an interactive shell on the agent. Click the view, then type.").size(12.5).color(p.text_muted));
            return;
        }

        // Connected: the terminal fills the remaining height; Disconnect and the
        // connection status live in the tab row above.
        egui::Frame::none()
            .fill(theme::TERM_BG)
            .stroke(Stroke::new(0.5_f32, p.border_strong))
            .rounding(8.0)
            .inner_margin(Margin::same(10.0))
            .show(ui, |ui| {
                self.term.as_mut().unwrap().ui(ui);
            });
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(40));
    }

    fn ui_exec(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str) {
        ui.label(RichText::new("Command").size(12.5).color(p.text_secondary));
        ui.add_space(4.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.exec_cmd)
                .desired_rows(3)
                .font(FontId::monospace(13.0))
                .desired_width(f32::INFINITY)
                .hint_text("Get-Service Spooler | Restart-Service"),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let shells = self
                .agents
                .iter()
                .find(|a| a.agent_id == agent_id)
                .map(|a| a.shells.clone())
                .unwrap_or_default();
            if !shells.is_empty() {
                ui.label(RichText::new("shell").size(12.5).color(p.text_secondary));
                egui::ComboBox::from_id_salt("exec_shell")
                    .selected_text(if self.exec_shell.is_empty() {
                        "default"
                    } else {
                        self.exec_shell.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for s in &shells {
                            ui.selectable_value(&mut self.exec_shell, s.clone(), s);
                        }
                    });
            }
            ui.label(RichText::new("timeout (s)").size(12.5).color(p.text_secondary));
            ui.add(egui::TextEdit::singleline(&mut self.exec_timeout).hint_text("default").desired_width(64.0));
            let ctx = ui.ctx().clone();
            let can_run = !self.exec_busy && !self.exec_cmd.trim().is_empty();
            if accent_button(ui, p, "Run", can_run).clicked() && can_run {
                self.do_exec(&ctx, agent_id);
            }
            if self.exec_busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
        });
        ui.add_space(8.0);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match &self.exec_result {
            None => {
                ui.label(RichText::new("Run a command to see its output.").size(12.5).color(p.text_muted));
            }
            Some(Err(e)) => {
                ui.label(RichText::new(e).color(p.danger));
            }
            Some(Ok(r)) => {
                ui.horizontal(|ui| {
                    match r.exit_code {
                        Some(0) => pill(ui, "exit 0", p.success, mix(p.success, p.page, 0.82)),
                        Some(c) => pill(ui, &format!("exit {c}"), p.danger, mix(p.danger, p.page, 0.82)),
                        None => pill(ui, "no exit code", p.warning, mix(p.warning, p.page, 0.82)),
                    }
                    if r.truncated {
                        ui.label(RichText::new("(truncated)").size(11.5).color(p.text_muted));
                    }
                });
                if let Some(err) = &r.error {
                    ui.label(RichText::new(err).color(p.danger));
                }
                if !r.stdout.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new("stdout").size(11.5).color(p.text_muted));
                    term_block(ui, &r.stdout);
                }
                if !r.stderr.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new("stderr").size(11.5).color(p.text_muted));
                    term_block(ui, &r.stderr);
                }
            }
        });
    }

    fn ui_confirm_uninstall(&mut self, ctx: &egui::Context) {
        let Some(agent_id) = self.confirm_uninstall.clone() else {
            return;
        };
        let p = theme::current(ctx);
        let mut open = true;
        let mut do_it = false;
        let mut cancel = false;
        egui::Window::new(RichText::new("Uninstall agent?").color(p.text))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .frame(egui::Frame::none().fill(p.card).stroke(Stroke::new(0.5_f32,p.border_strong)).rounding(12.0).inner_margin(Margin::same(16.0)))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(320.0);
                ui.label(RichText::new(format!("Tell “{agent_id}” to stop its service and delete itself from that machine?")));
                ui.add_space(4.0);
                ui.label(RichText::new("This can't be undone from here — you'd reinstall to get it back.").size(12.5).color(p.text_muted));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Uninstall").color(Color32::WHITE)).fill(p.danger)).clicked() {
                        do_it = true;
                    }
                    if ui.add(egui::Button::new("Cancel").fill(Color32::TRANSPARENT).stroke(Stroke::new(0.5_f32,p.border_strong))).clicked() {
                        cancel = true;
                    }
                });
            });
        if do_it {
            self.do_uninstall(ctx, &agent_id);
            self.confirm_uninstall = None;
        } else if cancel || !open {
            self.confirm_uninstall = None;
        }
    }
}

impl eframe::App for RustlitelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ensure_theme(ctx);
        self.drain(ctx);

        match self.auth {
            Auth::Unknown => {
                self.fetch_me(ctx);
                self.auth = Auth::Anon;
                let p = theme::current(ctx);
                egui::CentralPanel::default().frame(egui::Frame::none().fill(p.page)).show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.45);
                        ui.spinner();
                    });
                });
                return;
            }
            Auth::Anon => {
                self.ui_login(ctx);
                return;
            }
            Auth::Authed { .. } => {}
        }

        let now = ctx.input(|i| i.time);
        if now - self.last_agents_fetch > 5.0 && !self.agents_loading {
            self.last_agents_fetch = now;
            self.fetch_agents(ctx);
        }

        self.ui_header(ctx);
        if let Some(note) = self.note.clone() {
            let p = theme::current(ctx);
            egui::TopBottomPanel::bottom("note")
                .frame(egui::Frame::none().fill(p.card).inner_margin(Margin::symmetric(14.0, 8.0)).stroke(Stroke::new(0.5_f32,p.border)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&note).size(12.5).color(p.text_secondary));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(egui::Button::new(RichText::new("dismiss").size(12.0).color(p.text_muted)).fill(Color32::TRANSPARENT).stroke(Stroke::NONE)).clicked() {
                                self.note = None;
                            }
                        });
                    });
                });
        }
        self.ui_side(ctx);
        self.ui_central(ctx);
        self.ui_confirm_uninstall(ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "theme", &self.theme);
    }
}

// --- small painted widgets --------------------------------------------------

fn wordmark(ui: &mut egui::Ui, p: &Palette, size: f32) {
    ui.horizontal(|ui| {
        let d = size * 0.9;
        let (rect, _) = ui.allocate_exact_size(vec2(d, d), Sense::hover());
        ui.painter().rect_filled(rect, Rounding::same(d * 0.28), p.accent);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            ">_",
            FontId::monospace(size * 0.5),
            Color32::WHITE,
        );
        ui.add_space(2.0);
        ui.label(RichText::new("rustlitel").size(size).strong().color(p.text));
    });
}

fn user_chip(ui: &mut egui::Ui, p: &Palette, name: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 11.0, p.accent_muted);
        let initials: String = name.chars().take(2).collect();
        ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, initials, FontId::proportional(11.0), p.accent);
        ui.add_space(2.0);
        ui.label(RichText::new(name).size(13.0).color(p.text_secondary));
    });
}

fn dot(ui: &mut egui::Ui, color: Color32, d: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(d + 2.0, d + 2.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), d / 2.0, color);
}

fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(6.0)
        .inner_margin(Margin::symmetric(8.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.5).color(fg));
        });
}

/// Accent-filled button that dims its whole fill when disabled, instead of
/// muted text on a full-accent fill (which reads as broken).
fn accent_button(ui: &mut egui::Ui, p: &Palette, text: &str, enabled: bool) -> egui::Response {
    let (fill, fg) = if enabled {
        (p.accent, Color32::WHITE)
    } else {
        (mix(p.accent, p.card, 0.68), p.text_muted)
    };
    ui.add(egui::Button::new(RichText::new(text).color(fg)).fill(fill))
}

fn tab(ui: &mut egui::Ui, p: &Palette, text: &str, active: bool) -> egui::Response {
    let color = if active { p.text } else { p.text_secondary };
    let resp = ui.add(
        egui::Label::new(RichText::new(text).size(13.5).color(color).strong())
            .sense(Sense::click()),
    );
    if active {
        let r = resp.rect;
        ui.painter().hline(
            r.x_range(),
            r.bottom() + 6.0,
            Stroke::new(2.0_f32, p.accent),
        );
    }
    resp
}

fn agent_row(ui: &mut egui::Ui, p: &Palette, a: &AgentInfo, selected: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
    let painter = ui.painter();
    let bg = if selected {
        p.accent_muted
    } else if resp.hovered() {
        p.hover
    } else {
        Color32::TRANSPARENT
    };
    if bg != Color32::TRANSPARENT {
        painter.rect_filled(rect, Rounding::same(6.0), bg);
    }
    if selected {
        let bar = Rect::from_min_size(rect.min, vec2(2.0, rect.height()));
        painter.rect_filled(bar, Rounding::ZERO, p.accent);
    }
    let dot_c = if a.allow_remote { p.success } else { p.text_muted };
    painter.circle_filled(egui::pos2(rect.left() + 14.0, rect.center().y), 4.0, dot_c);
    painter.text(
        egui::pos2(rect.left() + 26.0, rect.top() + 7.0),
        egui::Align2::LEFT_TOP,
        &a.name,
        FontId::proportional(13.5),
        p.text,
    );
    let sub = if a.allow_remote {
        format!("{} · {}", short_os(&a.os), human_dur(a.connected_secs))
    } else {
        format!("{} · remote off", short_os(&a.os))
    };
    painter.text(
        egui::pos2(rect.left() + 26.0, rect.top() + 22.0),
        egui::Align2::LEFT_TOP,
        sub,
        FontId::proportional(11.5),
        p.text_muted,
    );
    resp
}

fn term_block(ui: &mut egui::Ui, text: &str) {
    egui::Frame::none()
        .fill(theme::TERM_BG)
        .rounding(8.0)
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(RichText::new(text).font(FontId::monospace(12.5)).color(theme::TERM_FG))
                    .wrap_mode(egui::TextWrapMode::Extend),
            );
        });
}

// --- helpers ----------------------------------------------------------------

fn short_os(os: &str) -> String {
    os.split_whitespace().next().unwrap_or(os).to_string()
}

fn human_dur(secs: u64) -> String {
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 90 * 60 {
        format!("{}m", secs / 60)
    } else if secs < 48 * 3600 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Blend `a` toward `b` by `t` (0 = all a, 1 = all b). Used for faint tinted pills.
fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 * (1.0 - t) + y as f32 * t) as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

fn json_post(url: String, body: String) -> ehttp::Request {
    let mut req = ehttp::Request::post(url, body.into_bytes());
    req.headers.insert("Content-Type", "application/json");
    req
}

fn spawn_json<T, F>(inbox: &Inbox, ctx: &egui::Context, req: ehttp::Request, make: F)
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(Result<T, String>) -> Msg + Send + 'static,
{
    let inbox = inbox.clone();
    let ctx = ctx.clone();
    ehttp::fetch(req, move |res| {
        let out = match res {
            Ok(r) if r.ok => serde_json::from_slice::<T>(&r.bytes).map_err(|e| e.to_string()),
            Ok(r) => Err(format!("HTTP {}", r.status)),
            Err(e) => Err(e),
        };
        inbox.lock().unwrap().push(make(out));
        ctx.request_repaint();
    });
}

#[cfg(target_arch = "wasm32")]
fn origins() -> (String, String) {
    let loc = web_sys::window().unwrap().location();
    let proto = loc.protocol().unwrap_or_else(|_| "https:".into());
    let host = loc.host().unwrap_or_default();
    let https = proto == "https:";
    (
        format!("{}//{}", proto, host),
        format!("{}://{}", if https { "wss" } else { "ws" }, host),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn origins() -> (String, String) {
    (
        "http://localhost:8080".to_string(),
        "ws://localhost:8080".to_string(),
    )
}

#[cfg(target_arch = "wasm32")]
fn navigate(url: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.location().set_href(url);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn navigate(_url: &str) {}
