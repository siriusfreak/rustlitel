//! Theme: dark / light / system preference, the egui visuals for each, and font
//! installation (IBM Plex Sans for the UI, JetBrains Mono for machine names and
//! the terminal). Colours follow the "Консоль rustlitel" design canvas.

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

/// Semantic + surface colours for one mode.
#[derive(Clone, Copy)]
pub struct Palette {
    pub page: Color32,
    pub card: Color32,
    pub hover: Color32,
    pub active: Color32,
    pub selected: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_muted: Color32,
    /// Fill of the primary button, the logo and the cursor.
    pub accent: Color32,
    /// Accent as text on this mode's surfaces (amber is unreadable on white).
    pub accent_text: Color32,
    /// Text on an accent fill.
    pub on_accent: Color32,
    pub success: Color32,
    pub danger: Color32,
    pub warning: Color32,
}

pub const DARK: Palette = Palette {
    page: Color32::from_rgb(0x11, 0x15, 0x1c),
    card: Color32::from_rgb(0x17, 0x1c, 0x25),
    hover: Color32::from_rgb(0x1f, 0x26, 0x31),
    active: Color32::from_rgb(0x28, 0x30, 0x3d),
    selected: Color32::from_rgb(0x2a, 0x2a, 0x22),
    border: Color32::from_rgb(0x2b, 0x33, 0x40),
    border_strong: Color32::from_rgb(0x3d, 0x47, 0x57),
    text: Color32::from_rgb(0xe8, 0xe6, 0xe1),
    text_secondary: Color32::from_rgb(0xa3, 0xa9, 0xb3),
    text_muted: Color32::from_rgb(0x85, 0x8d, 0x9a),
    accent: Color32::from_rgb(0xf0, 0xa8, 0x3a),
    accent_text: Color32::from_rgb(0xf0, 0xa8, 0x3a),
    on_accent: Color32::from_rgb(0x1a, 0x12, 0x04),
    success: Color32::from_rgb(0x4c, 0xc3, 0x8a),
    danger: Color32::from_rgb(0xf2, 0x70, 0x6a),
    warning: Color32::from_rgb(0xe3, 0xc0, 0x4b),
};

pub const LIGHT: Palette = Palette {
    page: Color32::from_rgb(0xee, 0xf0, 0xf2),
    card: Color32::from_rgb(0xff, 0xff, 0xff),
    hover: Color32::from_rgb(0xe5, 0xe8, 0xec),
    active: Color32::from_rgb(0xd9, 0xdd, 0xe3),
    selected: Color32::from_rgb(0xfb, 0xf0, 0xdc),
    border: Color32::from_rgb(0xd3, 0xd8, 0xde),
    border_strong: Color32::from_rgb(0xb4, 0xbb, 0xc4),
    text: Color32::from_rgb(0x1b, 0x20, 0x27),
    text_secondary: Color32::from_rgb(0x4d, 0x55, 0x60),
    text_muted: Color32::from_rgb(0x66, 0x70, 0x7c),
    accent: Color32::from_rgb(0xf0, 0xa8, 0x3a),
    accent_text: Color32::from_rgb(0x8f, 0x51, 0x00),
    on_accent: Color32::from_rgb(0x1a, 0x12, 0x04),
    success: Color32::from_rgb(0x12, 0x80, 0x4f),
    danger: Color32::from_rgb(0xc8, 0x32, 0x2b),
    warning: Color32::from_rgb(0x8a, 0x62, 0x00),
};

/// The terminal surface is dark in both modes.
pub const TERM_BG: Color32 = Color32::from_rgb(0x0b, 0x0e, 0x13);
pub const TERM_FG: Color32 = Color32::from_rgb(0xd9, 0xdc, 0xe1);

/// The UI's semibold face at `size`.
pub fn semibold(size: f32) -> egui::FontId {
    egui::FontId::new(size, FontFamily::Name("semibold".into()))
}

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
    v.extreme_bg_color = p.page;
    v.hyperlink_color = p.accent_text;
    v.selection.bg_fill = p.accent.linear_multiply(if dark { 0.35 } else { 0.25 });
    v.selection.stroke = egui::Stroke::new(1.0_f32,p.accent);
    v.window_stroke = egui::Stroke::new(1.0_f32, p.border);
    v.popup_shadow = egui::epaint::Shadow::NONE;
    v.window_shadow = egui::epaint::Shadow::NONE;

    let rounding = egui::Rounding::same(6.0);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.card;
    w.noninteractive.weak_bg_fill = p.card;
    w.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, p.border);
    w.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32,p.text_secondary);
    w.noninteractive.rounding = rounding;

    w.inactive.bg_fill = p.card;
    w.inactive.weak_bg_fill = p.card;
    w.inactive.bg_stroke = egui::Stroke::new(1.0_f32, p.border);
    w.inactive.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.inactive.rounding = rounding;
    w.inactive.expansion = 0.0;

    w.hovered.bg_fill = p.hover;
    w.hovered.weak_bg_fill = p.hover;
    w.hovered.bg_stroke = egui::Stroke::new(1.0_f32, p.border_strong);
    w.hovered.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.hovered.rounding = rounding;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.active;
    w.active.weak_bg_fill = p.active;
    w.active.bg_stroke = egui::Stroke::new(1.0_f32, p.accent);
    w.active.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.active.rounding = rounding;
    w.active.expansion = 0.0;

    w.open.bg_fill = p.hover;
    w.open.weak_bg_fill = p.hover;
    w.open.bg_stroke = egui::Stroke::new(1.0_f32, p.border);
    w.open.fg_stroke = egui::Stroke::new(1.0_f32,p.text);
    w.open.rounding = rounding;

    ctx.set_visuals(v);
}

/// Install Inter (proportional) + JetBrains Mono (monospace) and set text sizes.
/// Call once at startup.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "plex".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/IBMPlexSans-Regular.ttf")),
    );
    fonts.font_data.insert(
        "plex-semibold".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/IBMPlexSans-SemiBold.ttf")),
    );
    fonts.font_data.insert(
        "jbmono".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf")),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "plex".to_owned());
    // Falls back to the proportional stack for glyphs the face lacks.
    let fallback = fonts.families[&FontFamily::Proportional].clone();
    fonts.families.insert(
        FontFamily::Name("semibold".into()),
        std::iter::once("plex-semibold".to_owned()).chain(fallback).collect(),
    );
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
            (TextStyle::Button, FontId::new(13.0, Proportional)),
            (TextStyle::Small, FontId::new(12.0, Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, Monospace)),
        ]
        .into();
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
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
