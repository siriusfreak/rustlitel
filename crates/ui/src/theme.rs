//! Theme: dark / light / system preference, the egui visuals for each (built to
//! match the approved design mockup), and font installation (Inter for the UI,
//! JetBrains Mono for the terminal).

use egui::{Color32, FontFamily};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemePref {
    System,
    Light,
    Dark,
}

impl Default for ThemePref {
    fn default() -> Self {
        ThemePref::System
    }
}

impl ThemePref {
    pub const ALL: [ThemePref; 3] = [ThemePref::System, ThemePref::Light, ThemePref::Dark];

    pub fn label(self) -> &'static str {
        match self {
            ThemePref::System => "System",
            ThemePref::Light => "Light",
            ThemePref::Dark => "Dark",
        }
    }

    pub fn is_dark(self) -> bool {
        match self {
            ThemePref::Dark => true,
            ThemePref::Light => false,
            ThemePref::System => system_prefers_dark(),
        }
    }

    pub fn apply(self, ctx: &egui::Context) {
        apply_palette(ctx, if self.is_dark() { DARK } else { LIGHT });
    }
}

// --- palette ----------------------------------------------------------------

/// Semantic + surface colours for one mode. Mirrors the design tokens used in
/// the mockup so the egui build reads the same.
#[derive(Clone, Copy)]
pub struct Palette {
    pub page: Color32,
    pub card: Color32,
    pub hover: Color32,
    pub active: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub accent_muted: Color32,
    pub success: Color32,
    pub danger: Color32,
    pub warning: Color32,
}

pub const DARK: Palette = Palette {
    page: Color32::from_rgb(0x0e, 0x0f, 0x13),
    card: Color32::from_rgb(0x16, 0x18, 0x1f),
    hover: Color32::from_rgb(0x1d, 0x20, 0x29),
    active: Color32::from_rgb(0x24, 0x28, 0x33),
    border: Color32::from_rgb(0x2a, 0x2e, 0x38),
    border_strong: Color32::from_rgb(0x3a, 0x40, 0x4d),
    text: Color32::from_rgb(0xe6, 0xe8, 0xec),
    text_secondary: Color32::from_rgb(0x9a, 0xa3, 0xb2),
    text_muted: Color32::from_rgb(0x6b, 0x72, 0x80),
    accent: Color32::from_rgb(0x4f, 0x8c, 0xff),
    accent_muted: Color32::from_rgb(0x1a, 0x2a, 0x4a),
    success: Color32::from_rgb(0x30, 0xc8, 0x6a),
    danger: Color32::from_rgb(0xef, 0x53, 0x50),
    warning: Color32::from_rgb(0xf5, 0x9e, 0x0b),
};

pub const LIGHT: Palette = Palette {
    page: Color32::from_rgb(0xf3, 0xf4, 0xf6),
    card: Color32::from_rgb(0xff, 0xff, 0xff),
    hover: Color32::from_rgb(0xec, 0xee, 0xf2),
    active: Color32::from_rgb(0xe2, 0xe6, 0xee),
    border: Color32::from_rgb(0xe1, 0xe4, 0xea),
    border_strong: Color32::from_rgb(0xcd, 0xd2, 0xdb),
    text: Color32::from_rgb(0x1f, 0x23, 0x28),
    text_secondary: Color32::from_rgb(0x56, 0x5e, 0x6c),
    text_muted: Color32::from_rgb(0x8c, 0x93, 0xa1),
    accent: Color32::from_rgb(0x25, 0x63, 0xeb),
    accent_muted: Color32::from_rgb(0xe3, 0xec, 0xfd),
    success: Color32::from_rgb(0x16, 0xa3, 0x4a),
    danger: Color32::from_rgb(0xdc, 0x35, 0x35),
    warning: Color32::from_rgb(0xb4, 0x6a, 0x0a),
};

/// The terminal surface is always dark (as in the mockup), in both modes.
/// Kept clearly darker than the page so the terminal reads as a distinct inset.
pub const TERM_BG: Color32 = Color32::from_rgb(0x05, 0x06, 0x09);
pub const TERM_FG: Color32 = Color32::from_rgb(0xd7, 0xdd, 0xe6);

/// Resolve the current palette from the applied visuals (dark vs light).
pub fn current(ctx: &egui::Context) -> Palette {
    if ctx.style().visuals.dark_mode {
        DARK
    } else {
        LIGHT
    }
}

fn apply_palette(ctx: &egui::Context, p: Palette) {
    let dark = p.page == DARK.page;
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    v.dark_mode = dark;
    v.panel_fill = p.page;
    v.window_fill = p.card;
    v.faint_bg_color = p.hover;
    v.extreme_bg_color = p.card;
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent.linear_multiply(if dark { 0.35 } else { 0.25 });
    v.selection.stroke = egui::Stroke::new(1.0_f32,p.accent);
    v.window_stroke = egui::Stroke::new(0.5_f32,p.border);
    v.popup_shadow = egui::epaint::Shadow::NONE;
    v.window_shadow = egui::epaint::Shadow::NONE;

    let rounding = egui::Rounding::same(7.0);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.card;
    w.noninteractive.weak_bg_fill = p.card;
    w.noninteractive.bg_stroke = egui::Stroke::new(0.5_f32,p.border);
    w.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32,p.text_secondary);
    w.noninteractive.rounding = rounding;

    w.inactive.bg_fill = p.card;
    w.inactive.weak_bg_fill = p.card;
    w.inactive.bg_stroke = egui::Stroke::new(0.5_f32,p.border);
    w.inactive.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.inactive.rounding = rounding;
    w.inactive.expansion = 0.0;

    w.hovered.bg_fill = p.hover;
    w.hovered.weak_bg_fill = p.hover;
    w.hovered.bg_stroke = egui::Stroke::new(0.5_f32,p.border_strong);
    w.hovered.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.hovered.rounding = rounding;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.active;
    w.active.weak_bg_fill = p.active;
    w.active.bg_stroke = egui::Stroke::new(0.5_f32,p.accent);
    w.active.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.active.rounding = rounding;
    w.active.expansion = 0.0;

    w.open.bg_fill = p.hover;
    w.open.weak_bg_fill = p.hover;
    w.open.bg_stroke = egui::Stroke::new(0.5_f32,p.border);
    w.open.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.open.rounding = rounding;

    ctx.set_visuals(v);
}

/// Install Inter (proportional) + JetBrains Mono (monospace) and set text sizes.
/// Call once at startup.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "inter".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/Inter.ttf")),
    );
    fonts.font_data.insert(
        "jbmono".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf")),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "inter".to_owned());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "jbmono".to_owned());
    ctx.set_fonts(fonts);

    ctx.style_mut(|s| {
        use egui::{FontFamily::Monospace, FontFamily::Proportional, FontId, TextStyle};
        s.text_styles = [
            (TextStyle::Heading, FontId::new(18.0, Proportional)),
            (TextStyle::Body, FontId::new(14.0, Proportional)),
            (TextStyle::Button, FontId::new(13.5, Proportional)),
            (TextStyle::Small, FontId::new(12.0, Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, Monospace)),
        ]
        .into();
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
    });
}

#[cfg(target_arch = "wasm32")]
fn system_prefers_dark() -> bool {
    web_sys::window()
        .and_then(|w| w.match_media("(prefers-color-scheme: dark)").ok().flatten())
        .map(|m| m.matches())
        .unwrap_or(true)
}

#[cfg(not(target_arch = "wasm32"))]
fn system_prefers_dark() -> bool {
    true
}
