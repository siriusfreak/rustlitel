//! The rustlitel egui application: sign-in, the machine list, terminal, run
//! command, the add-a-machine dialog, uninstall, and the theme switch. Laid out
//! after the "Консоль rustlitel" design canvas.

use std::sync::{Arc, Mutex};

use egui::{vec2, Align, Color32, FontId, Layout, Margin, RichText, Rounding, Sense, Stroke};
use serde::Deserialize;

use crate::mobile;
use crate::term::{self, Terminal};
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
    me_requested: bool,
    oidc_enabled: bool,

    login_token: String,
    login_busy: bool,
    login_error: Option<String>,

    agents: Vec<AgentInfo>,
    agents_error: Option<String>,
    agents_loading: bool,
    last_agents_fetch: f64,
    selected: Option<String>,
    filter: String,
    /// Narrow screen: the agent list replaces the selected agent's view.
    show_agents: bool,

    tab: CentralTab,
    term: Option<Terminal>,
    term_shell: String,
    /// Room the terminal grid has, measured while it is drawn or about to be.
    term_area: egui::Vec2,

    exec_cmd: String,
    exec_shell: String,
    exec_timeout: String,
    exec_busy: bool,
    exec_result: Option<Result<ExecResp, String>>,

    show_add: bool,
    inst_os: String,
    inst_name: String,
    inst_busy: bool,
    inst_link: Option<InstallerLink>,
    inst_error: Option<String>,
    inst_copied: bool,

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
            me_requested: false,
            oidc_enabled: false,
            login_token: String::new(),
            login_busy: false,
            login_error: None,
            agents: Vec::new(),
            agents_error: None,
            agents_loading: false,
            last_agents_fetch: 0.0,
            selected: None,
            filter: String::new(),
            show_agents: false,
            tab: CentralTab::Terminal,
            term: None,
            term_shell: String::new(),
            term_area: vec2(640.0, 384.0),
            exec_cmd: String::new(),
            exec_shell: String::new(),
            exec_timeout: String::new(),
            exec_busy: false,
            exec_result: None,
            show_add: false,
            inst_os: "windows".to_string(),
            inst_name: String::new(),
            inst_busy: false,
            inst_link: None,
            inst_error: None,
            inst_copied: false,
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
                Ok(r) if r.status == 401 => Msg::LoginErr("That token was not accepted. Check it and try again.".to_string()),
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
        self.show_add = false;
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
                Msg::Agents(Err(e)) if e == "HTTP 401" => {
                    // The session is gone: show the way back in, not a red "401".
                    self.agents_loading = false;
                    self.auth = Auth::Anon;
                    self.reset_session_state();
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
                    self.note = Some("Uninstall sent. The machine will leave the list shortly.".into());
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

    fn modal_open(&self) -> bool {
        self.show_add || self.confirm_uninstall.is_some()
    }

    // --- sign in ---

    fn ui_login(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            let width = 340.0_f32.min(ui.available_width() - 32.0);
            ui.add_space((ui.available_height() * 0.32 - 40.0).max(24.0));
            ui.vertical_centered(|ui| {
                ui.allocate_ui_with_layout(vec2(width, 0.0), Layout::top_down_justified(Align::Min), |ui| {
                    ui.horizontal(|ui| {
                        logo(ui, &p, 28.0);
                        ui.label(RichText::new("rustlitel").font(theme::semibold(20.0)).color(p.text));
                    });
                    ui.add_space(10.0);
                    ui.label(RichText::new("Shells on your machines behind NAT. Sign in to see which ones are connected.").size(14.0).color(p.text_secondary));
                    ui.add_space(12.0);

                    // With Keycloak configured, that's the only web login: the
                    // operator token stays a CLI/script credential.
                    if self.oidc_enabled {
                        if ui.add(primary("Sign in with Keycloak", 40.0)).clicked() {
                            navigate(&self.url("/oauth2/login?rd=/"));
                        }
                    } else {
                        ui.label(RichText::new("Operator token").size(12.0).color(p.text_secondary));
                        let field = ui.add(
                            egui::TextEdit::singleline(&mut self.login_token)
                                .password(true)
                                .hint_text("Paste the operator token")
                                .margin(Margin::symmetric(10.0, 9.0))
                                .desired_width(f32::INFINITY),
                        );
                        mobile::text_target(field.rect);
                        ui.add_space(4.0);
                        let submit = (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            | ui.add(primary("Sign in", 40.0)).clicked();
                        if submit && !self.login_busy && !self.login_token.is_empty() {
                            self.do_login(ctx);
                        }
                    }
                    if self.login_busy {
                        ui.add(egui::Spinner::new().size(16.0));
                    }
                    if let Some(err) = &self.login_error {
                        ui.label(RichText::new(err).size(13.0).color(p.danger));
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new("You stay signed in on this device for 30 days.").size(12.0).color(p.text_muted));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| self.theme_switch(ui));
                });
            });
        });
    }

    fn theme_switch(&mut self, ui: &mut egui::Ui) {
        let labels = ThemePref::ALL.map(|t| t.label());
        let on = ThemePref::ALL.iter().position(|t| *t == self.theme).unwrap_or(0);
        if let Some(i) = segmented(ui, &labels, on) {
            self.theme = ThemePref::ALL[i];
        }
    }

    // --- top bar ---

    fn ui_header(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::TopBottomPanel::top("header")
            .exact_height(44.0)
            .frame(egui::Frame::none().fill(p.card).inner_margin(Margin::symmetric(14.0, 0.0)).stroke(Stroke::new(1.0_f32, p.border)))
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    logo(ui, &p, 20.0);
                    ui.label(RichText::new("rustlitel").font(theme::semibold(15.0)).color(p.text));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(plain("Log out", &p)).clicked() {
                            self.do_logout(ctx);
                        }
                        if let Auth::Authed { username: Some(u) } = &self.auth {
                            ui.label(RichText::new(u).size(13.0).color(p.text_secondary));
                        }
                        if !is_narrow(ctx) {
                            self.theme_switch(ui);
                        }
                    });
                });
            });
    }

    // --- machine list ---

    fn ui_side(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::SidePanel::left("agents")
            .resizable(false)
            .exact_width(248.0)
            .frame(egui::Frame::none().fill(p.card).inner_margin(Margin::same(12.0)).stroke(Stroke::new(1.0_f32, p.border)))
            .show(ctx, |ui| self.ui_agents(ui, &p));
    }

    fn ui_agents(&mut self, ui: &mut egui::Ui, p: &Palette) {
        egui::TopBottomPanel::bottom("add_machine_bar")
            .exact_height(control_height() + 12.0)
            .frame(egui::Frame::none().inner_margin(Margin { top: 10.0, bottom: 2.0, ..Margin::ZERO }))
            .show_separator_line(false)
            .show_inside(ui, |ui| {
                ui.vertical_centered_justified(|ui| {
                    if ui.add(ghost("Add machine", p).min_size(vec2(0.0, control_height()))).clicked() {
                        self.show_add = true;
                    }
                });
            });

        let filter = ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text("Filter machines")
                .margin(Margin::symmetric(10.0, if mobile::is_touch() { 14.0 } else { 8.0 }))
                .desired_width(f32::INFINITY),
        );
        mobile::text_target(filter.rect);
        ui.add_space(4.0);

        if let Some(err) = &self.agents_error {
            ui.label(RichText::new(format!("Could not load machines: {err}")).size(12.0).color(p.danger));
        }

        let needle = self.filter.trim().to_lowercase();
        let (on, off): (Vec<AgentInfo>, Vec<AgentInfo>) = self
            .agents
            .iter()
            .filter(|a| {
                needle.is_empty()
                    || a.name.to_lowercase().contains(&needle)
                    || a.agent_id.to_lowercase().contains(&needle)
                    || a.os.to_lowercase().contains(&needle)
            })
            .cloned()
            .partition(|a| a.allow_remote);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            if self.agents.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new(if self.agents_loading { "Loading machines…" } else { "No machines connected. Add one to get started." }).size(13.0).color(p.text_muted));
            } else if on.is_empty() && off.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Nothing matches this filter.").size(13.0).color(p.text_muted));
            }
            for (title, group) in [("Remote on", &on), ("Listed only", &off)] {
                if group.is_empty() {
                    continue;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(format!("{title} · {}", group.len())).size(12.0).color(p.text_secondary));
                });
                ui.add_space(2.0);
                for a in group {
                    let selected = self.selected.as_deref() == Some(&a.agent_id);
                    if agent_row(ui, p, a, selected).clicked() {
                        self.select_agent(&a.agent_id);
                        self.show_agents = false;
                    }
                }
            }
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

    // --- add a machine ---

    fn ui_add_machine(&mut self, ctx: &egui::Context) {
        if !self.show_add {
            return;
        }
        let p = theme::current(ctx);
        let mut close = scrim(ctx);
        let width = 480.0_f32.min(ctx.screen_rect().width() - 24.0);
        dialog("Add a machine", width, &p).show(ctx, |ui| {
            ui.set_width(width - 40.0);
            row(ui, 30.0, |ui| {
                ui.label(RichText::new("Add a machine").font(theme::semibold(16.0)).color(p.text));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(plain("Close", &p)).clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(8.0);

            const OS: [(&str, &str); 3] = [("Windows", "windows"), ("macOS", "macos"), ("Linux", "linux")];
            row(ui, 36.0, |ui| {
                ui.label(RichText::new("System").size(12.0).color(p.text_secondary));
                let on = OS.iter().position(|o| o.1 == self.inst_os).unwrap_or(0);
                if let Some(i) = segmented(ui, &OS.map(|o| o.0), on) {
                    self.inst_os = OS[i].1.to_string();
                    self.inst_link = None;
                }
            });
            ui.add_space(6.0);
            row(ui, 36.0, |ui| {
                ui.label(RichText::new("Name").size(12.0).color(p.text_secondary));
                let name = ui.add(
                    egui::TextEdit::singleline(&mut self.inst_name)
                        .hint_text("Defaults to the hostname")
                        .margin(Margin::symmetric(10.0, 7.0))
                        .desired_width(f32::INFINITY),
                );
                mobile::text_target(name.rect);
                if name.changed() {
                    self.inst_link = None;
                }
            });
            ui.add_space(10.0);

            if let Some(link) = &self.inst_link {
                let url = link.url.clone();
                let days = link.expires_days;
                let windows = self.inst_os == "windows";
                let (hint, shown) = if windows {
                    (format!("Open this link on that machine and run the file it downloads. The link works for {days} days, and anyone holding it can add a machine."), url.clone())
                } else {
                    // Through curl: a browser download is not executable and
                    // macOS quarantines it.
                    (format!("Run this in a terminal on that machine. The link works for {days} days, and anyone holding it can add a machine."),
                     format!("curl -fsSL {url} -o rustlitel-agent && chmod +x rustlitel-agent && ./rustlitel-agent"))
                };
                ui.label(RichText::new(hint).size(13.0).color(p.text_secondary));
                ui.add_space(4.0);
                let mut readonly = shown.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut readonly)
                        .font(FontId::monospace(12.0))
                        .desired_rows(if windows { 2 } else { 4 })
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.add(primary(if windows { "Copy link" } else { "Copy command" }, control_height())).clicked() {
                        ctx.copy_text(shown.clone());
                        self.inst_copied = true;
                    }
                    if !windows && ui.add(ghost("Copy link", &p).min_size(vec2(0.0, control_height()))).clicked() {
                        ctx.copy_text(url.clone());
                        self.inst_copied = true;
                    }
                    if self.inst_copied {
                        ui.label(RichText::new("Copied").size(12.0).color(p.success));
                    }
                });
            } else if ui.add_enabled(!self.inst_busy, primary("Create link", control_height())).clicked() {
                self.inst_copied = false;
                self.do_installer(ctx);
            }
            if self.inst_busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
            if let Some(err) = &self.inst_error {
                ui.label(RichText::new(err).size(13.0).color(p.danger));
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Stock binaries").size(13.0).color(p.text_secondary));
                for (label, file) in [
                    ("Windows", "rustlitel-agent-windows.exe"),
                    ("macOS", "rustlitel-agent-macos"),
                    ("Linux", "rustlitel-agent-linux"),
                    ("CLI for macOS", "rustlitel-cli-macos"),
                ] {
                    ui.hyperlink_to(RichText::new(label).size(13.0), self.url(&format!("/download/{file}")));
                }
            });
        });
        if close {
            self.show_add = false;
        }
    }

    // --- selected machine ---

    fn ui_central(&mut self, ctx: &egui::Context) {
        let p = theme::current(ctx);
        egui::CentralPanel::default().frame(egui::Frame::none().fill(p.page)).show(ctx, |ui| {
            let Some(agent_id) = self.selected.clone() else {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.42);
                    ui.label(RichText::new("Pick a machine on the left.").size(14.0).color(p.text_muted));
                });
                return;
            };
            let agent = self.agents.iter().find(|a| a.agent_id == agent_id).cloned();
            self.ui_machine_head(ui, &p, &agent_id, agent.as_ref());
            match self.tab {
                CentralTab::Terminal => self.ui_terminal(ui, &p, &agent_id, agent.as_ref()),
                CentralTab::Exec => self.ui_exec(ui, &p, &agent_id, agent.as_ref()),
            }
        });
    }

    fn ui_machine_head(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str, agent: Option<&AgentInfo>) {
        let narrow = is_narrow(ui.ctx());
        let name = agent.map_or(agent_id, |a| a.name.as_str()).to_string();
        let tabs = ["Terminal", "Run command"];
        let tab_on = if self.tab == CentralTab::Terminal { 0 } else { 1 };
        let term_state = self.term.as_ref().map(|t| (t.open, t.closed, t.status.clone()));

        let head = egui::Frame::none()
            .fill(if narrow { p.card } else { p.page })
            .inner_margin(if narrow { Margin::symmetric(6.0, 4.0) } else { Margin::symmetric(16.0, 11.0) })
            .show(ui, |ui| {
                row(ui, if narrow { 44.0 } else { 30.0 }, |ui| {
                    if narrow && ui.add(plain("\u{2190} Machines", p).min_size(vec2(0.0, 44.0))).clicked() {
                        self.show_agents = true;
                    }
                    ui.label(RichText::new(&name).font(FontId::monospace(if narrow { 13.0 } else { 15.0 })).strong().color(p.text));
                    if !narrow {
                        let sub = agent.map_or("not connected".to_string(), |a| a.os.replace(' ', " · "));
                        ui.label(RichText::new(sub).size(12.0).color(p.text_muted));
                        ui.add_space(4.0);
                        if let Some(i) = segmented(ui, &tabs, tab_on) {
                            self.tab = if i == 0 { CentralTab::Terminal } else { CentralTab::Exec };
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        self.ui_head_actions(ui, p, agent_id, narrow, term_state.as_ref());
                    });
                });
                if narrow {
                    ui.horizontal(|ui| {
                        ui.add_space(6.0);
                        if let Some(i) = segmented(ui, &tabs, tab_on) {
                            self.tab = if i == 0 { CentralTab::Terminal } else { CentralTab::Exec };
                        }
                    });
                }
            });
        ui.painter().hline(ui.max_rect().x_range(), head.response.rect.bottom(), Stroke::new(1.0_f32, p.border));
    }

    fn ui_head_actions(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str, narrow: bool, term: Option<&(bool, bool, String)>) {
        let height = if narrow { 44.0 } else { 30.0 };
        match (self.tab, term) {
            (CentralTab::Terminal, Some((open, closed, status))) => {
                if *closed {
                    if ui.add(primary("Reconnect", height)).clicked() {
                        self.open_terminal(ui.ctx(), agent_id);
                    }
                    if ui.add(ghost("Close", p).min_size(vec2(0.0, height))).clicked() {
                        self.term = None;
                    }
                    ui.label(RichText::new(status).size(12.0).color(p.text_muted));
                } else {
                    if ui.add(ghost(if narrow { "End" } else { "Disconnect" }, p).min_size(vec2(0.0, height))).clicked() {
                        self.term = None;
                    }
                    let (c, label) = if *open { (p.success, "connected") } else { (p.warning, "connecting…") };
                    ui.label(RichText::new(label).size(12.0).color(c));
                    dot(ui, c, 7.0);
                }
            }
            _ => {
                let uninstall = egui::Button::new(RichText::new(if narrow { "Uninstall" } else { "Uninstall agent" }).size(13.0).color(p.danger))
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .min_size(vec2(0.0, height));
                if ui.add(uninstall).clicked() {
                    self.confirm_uninstall = Some(agent_id.to_string());
                }
            }
        }
    }

    fn open_terminal(&mut self, ctx: &egui::Context, agent_id: &str) {
        let shell = (!self.term_shell.is_empty()).then(|| self.term_shell.clone());
        let grid = term::grid_for(ctx, self.term_area);
        match Terminal::connect(&self.ws_origin, agent_id, shell.as_deref(), ctx, grid) {
            Ok(t) => self.term = Some(t),
            Err(e) => self.note = Some(format!("Could not open the terminal: {e}")),
        }
    }

    fn ui_terminal(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str, agent: Option<&AgentInfo>) {
        // Everything around the grid: frame margins, and the status or key bar.
        let chrome = if mobile::is_touch() { vec2(12.0, 12.0 + term::KEY_BAR_HEIGHT) } else { vec2(28.0, 24.0 + 26.0) };
        self.term_area = ui.available_size() - chrome;
        if self.term.is_none() {
            egui::Frame::none().inner_margin(Margin::same(24.0)).show(ui, |ui| {
                let Some(a) = agent else {
                    ui.label(RichText::new("This machine is not connected right now. Its agent reconnects on its own.").size(14.0).color(p.text_secondary));
                    return;
                };
                if !a.allow_remote {
                    remote_off_note(ui, p);
                    return;
                }
                ui.label(RichText::new(format!("Open a shell on {}", a.name)).font(theme::semibold(16.0)).color(p.text));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    shell_combo(ui, "term_shell", &mut self.term_shell, &a.shells);
                    if ui.add(primary("Open terminal", control_height())).clicked() {
                        self.open_terminal(ui.ctx(), agent_id);
                    }
                });
            });
            return;
        }

        let capture = !self.modal_open();
        let now = ui.input(|i| i.time);
        if !mobile::is_touch() {
            let t = self.term.as_ref().unwrap();
            let scrolled = t.scrolled_back();
            let right = match (scrolled, t.opened_at) {
                (n, _) if n > 0 => format!("{n} lines back, type to return"),
                (_, Some(at)) => format!("session {}", human_dur((now - at).max(0.0) as u64)),
                _ => String::new(),
            };
            let left = format!("{}   {}×{}   drag to copy", self.term_shell, t.cols, t.rows);
            egui::TopBottomPanel::bottom("term_status")
                .exact_height(26.0)
                .frame(egui::Frame::none().fill(p.card).inner_margin(Margin::symmetric(14.0, 0.0)))
                .show_separator_line(false)
                .show_inside(ui, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.label(RichText::new(left).font(FontId::monospace(12.0)).color(p.text_muted));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(right).font(FontId::monospace(12.0)).color(p.text_muted));
                        });
                    });
                });
        }
        egui::Frame::none()
            .fill(theme::TERM_BG)
            .inner_margin(if mobile::is_touch() { Margin::same(6.0) } else { Margin::symmetric(14.0, 12.0) })
            .show(ui, |ui| {
                self.term.as_mut().unwrap().ui(ui, capture);
            });
        // The session age in the status bar.
        ui.ctx().request_repaint_after(std::time::Duration::from_secs(30));
    }

    fn ui_exec(&mut self, ui: &mut egui::Ui, p: &Palette, agent_id: &str, agent: Option<&AgentInfo>) {
        if agent.is_some_and(|a| !a.allow_remote) {
            egui::Frame::none().inner_margin(Margin::same(24.0)).show(ui, |ui| remote_off_note(ui, p));
            return;
        }
        let shells = agent.map(|a| a.shells.clone()).unwrap_or_default();
        egui::Frame::none().inner_margin(Margin::same(16.0)).show(ui, |ui| {
            let run_shortcut = ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter));
            let cmd = ui.add(
                egui::TextEdit::multiline(&mut self.exec_cmd)
                    .desired_rows(3)
                    .font(FontId::monospace(13.0))
                    .margin(Margin::symmetric(12.0, 10.0))
                    .desired_width(f32::INFINITY)
                    .hint_text("Get-Service Spooler | Restart-Service"),
            );
            mobile::text_target(cmd.rect);
            ui.add_space(8.0);
            let can_run = !self.exec_busy && !self.exec_cmd.trim().is_empty();
            let mut run = run_shortcut && can_run;
            ui.horizontal_wrapped(|ui| {
                shell_combo(ui, "exec_shell", &mut self.exec_shell, &shells);
                ui.label(RichText::new("Timeout, s").size(12.0).color(p.text_secondary));
                let timeout = ui.add(
                    egui::TextEdit::singleline(&mut self.exec_timeout)
                        .hint_text("120")
                        .margin(Margin::symmetric(8.0, 6.0))
                        .desired_width(52.0),
                );
                mobile::text_target(timeout.rect);
                run |= ui.add_enabled(can_run, primary("Run", control_height())).clicked();
                if self.exec_busy {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label(RichText::new("Running…").size(12.0).color(p.text_muted));
                }
            });
            if run {
                self.do_exec(ui.ctx(), agent_id);
            }
            ui.add_space(12.0);

            match &self.exec_result {
                None => {
                    ui.label(RichText::new("Output appears here.").size(13.0).color(p.text_muted));
                }
                Some(Err(e)) => {
                    ui.label(RichText::new(format!("The command did not run: {e}")).size(13.0).color(p.danger));
                }
                Some(Ok(r)) => {
                    ui.horizontal(|ui| {
                        match r.exit_code {
                            Some(0) => pill(ui, "exit 0", p.success, mix(p.success, p.page, 0.85)),
                            Some(c) => pill(ui, &format!("exit {c}"), p.danger, mix(p.danger, p.page, 0.85)),
                            None => pill(ui, "no exit code", p.warning, mix(p.warning, p.page, 0.85)),
                        }
                        if r.truncated {
                            ui.label(RichText::new("Output was cut at the relay's limit.").size(12.0).color(p.text_muted));
                        }
                    });
                    if let Some(err) = &r.error {
                        ui.label(RichText::new(err).size(13.0).color(p.danger));
                    }
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(theme::TERM_BG)
                        .rounding(6.0)
                        .inner_margin(Margin::symmetric(14.0, 12.0))
                        .show(ui, |ui| {
                            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                                if r.stdout.is_empty() && r.stderr.is_empty() {
                                    ui.label(RichText::new("The command printed nothing.").font(FontId::monospace(13.0)).color(p.text_muted));
                                }
                                output_block(ui, &r.stdout, theme::TERM_FG);
                                output_block(ui, &r.stderr, theme::DARK.danger);
                            });
                        });
                }
            }
        });
    }

    fn ui_confirm_uninstall(&mut self, ctx: &egui::Context) {
        let Some(agent_id) = self.confirm_uninstall.clone() else {
            return;
        };
        let p = theme::current(ctx);
        let mut cancel = scrim(ctx);
        let mut do_it = false;
        let width = 400.0_f32.min(ctx.screen_rect().width() - 24.0);
        dialog("Uninstall agent", width, &p).show(ctx, |ui| {
            ui.set_width(width - 40.0);
            ui.label(RichText::new(format!("Uninstall the agent on {agent_id}?")).font(theme::semibold(16.0)).color(p.text));
            ui.add_space(6.0);
            ui.label(RichText::new("It stops its service and deletes itself. To get this machine back you need access to it by other means, to install the agent again.").size(13.0).color(p.text_secondary));
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                let danger = egui::Button::new(RichText::new("Uninstall agent").size(13.0).color(Color32::WHITE))
                    .fill(p.danger)
                    .min_size(vec2(0.0, control_height()));
                do_it = ui.add(danger).clicked();
                cancel |= ui.add(ghost("Keep it", &p).min_size(vec2(0.0, control_height()))).clicked();
            });
        });
        if do_it {
            self.do_uninstall(ctx, &agent_id);
            self.confirm_uninstall = None;
        } else if cancel {
            self.confirm_uninstall = None;
        }
    }
}

impl eframe::App for RustlitelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        mobile::begin_frame();
        self.ensure_theme(ctx);
        self.drain(ctx);
        let now = ctx.input(|i| i.time);
        if let Some(t) = self.term.as_mut() {
            t.pump(now);
        }

        match self.auth {
            Auth::Unknown => {
                if !self.me_requested {
                    self.me_requested = true;
                    self.fetch_me(ctx);
                }
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

        // Without this nothing wakes an idle page, and the list goes stale.
        if now - self.last_agents_fetch > AGENTS_POLL_SECS && !self.agents_loading {
            self.last_agents_fetch = now;
            self.fetch_agents(ctx);
        }
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(AGENTS_POLL_SECS));

        let narrow = is_narrow(ctx);
        let list_screen = narrow && (self.show_agents || self.selected.is_none());
        if !narrow || list_screen {
            self.ui_header(ctx);
        }
        if let Some(note) = self.note.clone() {
            let p = theme::current(ctx);
            egui::TopBottomPanel::bottom("note")
                .frame(egui::Frame::none().fill(p.card).inner_margin(Margin::symmetric(14.0, 8.0)).stroke(Stroke::new(1.0_f32, p.border)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&note).size(13.0).color(p.text_secondary));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(plain("Dismiss", &p)).clicked() {
                                self.note = None;
                            }
                        });
                    });
                });
        }
        if list_screen {
            let p = theme::current(ctx);
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(p.page).inner_margin(Margin::same(12.0)))
                .show(ctx, |ui| self.ui_agents(ui, &p));
        } else {
            if !narrow {
                self.ui_side(ctx);
            }
            self.ui_central(ctx);
        }
        self.ui_add_machine(ctx);
        self.ui_confirm_uninstall(ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "theme", &self.theme);
    }
}

// --- layout rules -----------------------------------------------------------

const AGENTS_POLL_SECS: f64 = 5.0;

/// Too narrow for the machine list next to the terminal (a phone held upright).
fn is_narrow(ctx: &egui::Context) -> bool {
    ctx.screen_rect().width() < 700.0
}

/// Fingers need 44 pt; a mouse does not.
fn control_height() -> f32 {
    if mobile::is_touch() {
        44.0
    } else {
        30.0
    }
}

// --- widgets ----------------------------------------------------------------

/// A left-to-right row of the given height with everything centred on one line.
fn row(ui: &mut egui::Ui, height: f32, add: impl FnOnce(&mut egui::Ui)) {
    let size = vec2(ui.available_width(), height);
    ui.allocate_ui_with_layout(size, Layout::left_to_right(Align::Center), add);
}

fn primary(text: &str, height: f32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).font(theme::semibold(13.0)).color(theme::DARK.on_accent))
        .fill(theme::DARK.accent)
        .stroke(Stroke::NONE)
        .min_size(vec2(0.0, height))
}

fn ghost(text: &str, p: &Palette) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(13.0).color(p.text_secondary))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0_f32, p.border))
        .min_size(vec2(0.0, 30.0))
}

fn plain(text: &str, p: &Palette) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(13.0).color(p.text_secondary))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE)
}

/// A row of mutually exclusive options; returns the one just clicked. Keeps its
/// reading order inside a right-to-left parent.
fn segmented(ui: &mut egui::Ui, labels: &[&str], on: usize) -> Option<usize> {
    let p = theme::current(ui.ctx());
    let height = if mobile::is_touch() { 36.0 } else { 24.0 };
    let mut clicked = None;
    egui::Frame::none()
        .stroke(Stroke::new(1.0_f32, p.border))
        .rounding(7.0)
        .inner_margin(Margin::same(2.0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                let reversed = ui.layout().main_dir() == egui::Direction::RightToLeft;
                let mut order: Vec<usize> = (0..labels.len()).collect();
                if reversed {
                    order.reverse();
                }
                for i in order {
                    let active = i == on;
                    let text = RichText::new(labels[i]).size(12.0).color(if active { p.text } else { p.text_secondary });
                    let button = egui::Button::new(text)
                        .fill(if active { p.hover } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE)
                        .rounding(5.0)
                        .min_size(vec2(0.0, height));
                    if ui.add(button).clicked() {
                        clicked = Some(i);
                    }
                }
            });
        });
    clicked
}

fn shell_combo(ui: &mut egui::Ui, id: &str, value: &mut String, shells: &[String]) {
    if shells.is_empty() {
        return;
    }
    egui::ComboBox::from_id_salt(id)
        .selected_text(if value.is_empty() { "default shell" } else { value.as_str() })
        .show_ui(ui, |ui| {
            for s in shells {
                ui.selectable_value(value, s.clone(), s);
            }
        });
}

fn remote_off_note(ui: &mut egui::Ui, p: &Palette) {
    ui.label(RichText::new("Remote access is off on this machine").font(theme::semibold(16.0)).color(p.text));
    ui.add_space(6.0);
    ui.label(RichText::new("Its agent runs without --allow-remote, so it shows up here but declines shells and commands. Restart it with that flag to use it.").size(13.0).color(p.text_secondary));
}

/// Dims the page behind a dialog and swallows its clicks. True when clicked.
fn scrim(ctx: &egui::Context) -> bool {
    let screen = ctx.screen_rect();
    egui::Area::new(egui::Id::new("scrim"))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            ui.painter().rect_filled(screen, 0.0, Color32::from_black_alpha(158));
            ui.allocate_rect(screen, Sense::click()).clicked()
        })
        .inner
}

fn dialog<'a>(id: &'a str, width: f32, p: &Palette) -> egui::Window<'a> {
    egui::Window::new(id)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .fixed_size(vec2(width - 40.0, 0.0))
        .frame(egui::Frame::none().fill(p.card).stroke(Stroke::new(1.0_f32, p.border)).rounding(10.0).inner_margin(Margin::same(20.0)))
}

fn logo(ui: &mut egui::Ui, p: &Palette, size: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    ui.painter().rect_filled(rect, Rounding::same(size * 0.26), p.accent);
    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, ">_", FontId::monospace(size * 0.5), p.on_accent);
}

fn dot(ui: &mut egui::Ui, color: Color32, d: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(d + 2.0, d + 2.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), d / 2.0, color);
}

fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(4.0)
        .inner_margin(Margin::symmetric(8.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).font(FontId::monospace(12.0)).color(fg));
        });
}

fn agent_row(ui: &mut egui::Ui, p: &Palette, a: &AgentInfo, selected: bool) -> egui::Response {
    let height = if mobile::is_touch() { 52.0 } else { 44.0 };
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    let painter = ui.painter();
    let bg = if selected {
        p.selected
    } else if resp.hovered() {
        p.hover
    } else {
        Color32::TRANSPARENT
    };
    painter.rect_filled(rect, Rounding::same(6.0), bg);
    // Filled when it takes commands, hollow when only listed: shape, not hue alone.
    let center = egui::pos2(rect.left() + 14.0, rect.center().y);
    if a.allow_remote {
        painter.circle_filled(center, 4.0, p.success);
    } else {
        painter.circle_stroke(center, 3.5, Stroke::new(1.5_f32, p.text_muted));
    }
    let line = rect.center().y;
    painter.text(egui::pos2(rect.left() + 28.0, line + 1.0), egui::Align2::LEFT_BOTTOM, &a.name, FontId::monospace(13.0), p.text);
    let sub = if a.allow_remote {
        format!("{} · up {}", short_os(&a.os), human_dur(a.connected_secs))
    } else {
        format!("{} · remote off", short_os(&a.os))
    };
    painter.text(egui::pos2(rect.left() + 28.0, line + 2.0), egui::Align2::LEFT_TOP, sub, FontId::proportional(12.0), p.text_muted);
    resp
}

fn output_block(ui: &mut egui::Ui, text: &str, color: Color32) {
    if !text.is_empty() {
        ui.add(egui::Label::new(RichText::new(text).font(FontId::monospace(13.0)).color(color)).wrap_mode(egui::TextWrapMode::Extend));
    }
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
