//! Semantic color theme. All views read colors from this single `Theme`.
//!
//! The default palette matches sofka.rs's default skin (catppuccin-mocha);
//! a sofka config (`~/.config/sofka/config.toml` + `conf.d/*.toml`) can be
//! reused through [`sofka::load_theme`] (see [`Theme::load_sofka_or_default`]).

use ratatui::style::Color;

/// The sofka 25-swatch palette (catppuccin layout), used both as our default
/// palette and as the target of `[skin.colors]` overrides from a sofka config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    missing_docs,
    reason = "pure data table: the 25 swatch names are self-documenting"
)]
pub struct SofkaPalette {
    pub rosewater: Color,
    pub flamingo: Color,
    pub pink: Color,
    pub mauve: Color,
    pub red: Color,
    pub maroon: Color,
    pub peach: Color,
    pub yellow: Color,
    pub green: Color,
    pub teal: Color,
    pub sky: Color,
    pub sapphire: Color,
    pub blue: Color,
    pub lavender: Color,
    pub text: Color,
    pub subtext1: Color,
    pub subtext0: Color,
    pub overlay1: Color,
    pub overlay0: Color,
    pub surface2: Color,
    pub surface1: Color,
    pub surface0: Color,
    pub base: Color,
    pub mantle: Color,
    pub crust: Color,
}

/// sofka's built-in skin name → palette, for the skins we embed. Unknown names
/// resolve to `None` and fall back to mocha with a warning.
#[must_use]
pub fn sofka_skin(name: &str) -> Option<SofkaPalette> {
    match name {
        "catppuccin-mocha" | "mocha" => Some(catppuccin_mocha()),
        "catppuccin-latte" | "latte" => Some(catppuccin_latte()),
        "catppuccin-frappe" | "frappe" => Some(catppuccin_frappe()),
        "catppuccin-macchiato" | "macchiato" => Some(catppuccin_macchiato()),
        "gruvbox-dark" | "gruvbox" => Some(gruvbox_dark()),
        _ => None,
    }
}

/// catppuccin-mocha, sofka's hardcoded fallback/default palette.
#[must_use]
pub const fn catppuccin_mocha() -> SofkaPalette {
    SofkaPalette {
        rosewater: c(0xf5_e0_dc),
        flamingo: c(0xf2_cd_cd),
        pink: c(0xf5_c2_e7),
        mauve: c(0xcb_a6_f7),
        red: c(0xf3_8b_a8),
        maroon: c(0xeb_a0_ac),
        peach: c(0xfa_b3_87),
        yellow: c(0xf9_e2_af),
        green: c(0xa6_e3_a1),
        teal: c(0x94_e2_d5),
        sky: c(0x89_dc_eb),
        sapphire: c(0x74_c7_ec),
        blue: c(0x89_b4_fa),
        lavender: c(0xb4_be_fe),
        text: c(0xcd_d6_f4),
        subtext1: c(0xba_c2_de),
        subtext0: c(0xa6_ad_c8),
        overlay1: c(0x7f_84_9c),
        overlay0: c(0x6c_70_86),
        surface2: c(0x58_5b_70),
        surface1: c(0x45_47_5a),
        surface0: c(0x31_32_44),
        base: c(0x1e_1e_2e),
        mantle: c(0x18_18_25),
        crust: c(0x11_11_1b),
    }
}

/// catppuccin-latte (used when a sofka config selects it).
#[must_use]
pub const fn catppuccin_latte() -> SofkaPalette {
    SofkaPalette {
        rosewater: c(0xdc_8a_78),
        flamingo: c(0xdd_78_78),
        pink: c(0xea_76_cb),
        mauve: c(0x88_39_ef),
        red: c(0xd2_0f_39),
        maroon: c(0xe6_45_53),
        peach: c(0xfe_64_0b),
        yellow: c(0xdf_8e_1d),
        green: c(0x40_a0_2b),
        teal: c(0x17_92_99),
        sky: c(0x04_a5_e5),
        sapphire: c(0x20_9f_b5),
        blue: c(0x1e_66_f5),
        lavender: c(0x72_87_fd),
        text: c(0x4c_4f_69),
        subtext1: c(0x5c_5f_77),
        subtext0: c(0x6c_6f_85),
        overlay1: c(0x7c_7f_93),
        overlay0: c(0x8c_8f_a1),
        surface2: c(0xac_b0_be),
        surface1: c(0xcc_d0_da),
        surface0: c(0xef_f1_f5),
        base: c(0xef_f1_f5),
        mantle: c(0xe6_e9_ef),
        crust: c(0xdc_e0_e8),
    }
}

/// catppuccin-frappe.
#[must_use]
pub const fn catppuccin_frappe() -> SofkaPalette {
    SofkaPalette {
        rosewater: c(0xf2_d5_cf),
        flamingo: c(0xee_be_be),
        pink: c(0xf4_b8_e4),
        mauve: c(0xca_9e_e6),
        red: c(0xe7_82_84),
        maroon: c(0xea_99_9c),
        peach: c(0xef_9f_76),
        yellow: c(0xe5_c8_90),
        green: c(0xa6_d1_89),
        teal: c(0x81_c8_be),
        sky: c(0x99_d1_db),
        sapphire: c(0x85_c1_dc),
        blue: c(0x8c_aa_ee),
        lavender: c(0xba_bb_f1),
        text: c(0xc6_d0_f5),
        subtext1: c(0xb5_bf_e2),
        subtext0: c(0xa5_ad_ce),
        overlay1: c(0x83_8b_a7),
        overlay0: c(0x73_79_94),
        surface2: c(0x62_68_80),
        surface1: c(0x51_57_6d),
        surface0: c(0x41_45_59),
        base: c(0x30_34_46),
        mantle: c(0x29_2c_3c),
        crust: c(0x23_26_34),
    }
}

/// catppuccin-macchiato.
#[must_use]
#[allow(
    clippy::mistyped_literal_suffixes,
    reason = "0x49_4d_64 byte-pair separators are deliberate; clippy misreads `_64` as an int suffix"
)]
pub const fn catppuccin_macchiato() -> SofkaPalette {
    SofkaPalette {
        rosewater: c(0xf4_db_d6),
        flamingo: c(0xf0_c6_c6),
        pink: c(0xf5_bd_e6),
        mauve: c(0xc6_a0_f6),
        red: c(0xed_87_96),
        maroon: c(0xee_99_a0),
        peach: c(0xf5_a9_7f),
        yellow: c(0xee_d4_9f),
        green: c(0xa6_da_95),
        teal: c(0x8b_d5_ca),
        sky: c(0x91_d7_e3),
        sapphire: c(0x7d_c4_e4),
        blue: c(0x8a_ad_f4),
        lavender: c(0xb7_bd_f8),
        text: c(0xca_d3_f5),
        subtext1: c(0xb8_c0_e0),
        subtext0: c(0xa5_ad_cb),
        overlay1: c(0x80_87_a2),
        overlay0: c(0x6e_73_8d),
        surface2: c(0x5b_60_78),
        surface1: c(0x49_4d_64),
        surface0: c(0x36_3a_4f),
        base: c(0x24_27_3a),
        mantle: c(0x1e_20_30),
        crust: c(0x18_19_26),
    }
}

/// gruvbox-dark.
#[must_use]
pub const fn gruvbox_dark() -> SofkaPalette {
    SofkaPalette {
        rosewater: c(0xeb_db_b2),
        flamingo: c(0xd5_c4_a1),
        pink: c(0xd3_86_9b),
        mauve: c(0xd3_86_9b),
        red: c(0xfb_49_34),
        maroon: c(0xcc_24_1d),
        peach: c(0xfe_80_19),
        yellow: c(0xfa_bd_2f),
        green: c(0xb8_bb_26),
        teal: c(0x8e_c0_7c),
        sky: c(0x83_a5_98),
        sapphire: c(0x45_85_88),
        blue: c(0x83_a5_98),
        lavender: c(0xd3_86_9b),
        text: c(0xeb_db_b2),
        subtext1: c(0xd5_c4_a1),
        subtext0: c(0xbd_ae_93),
        overlay1: c(0xa8_99_84),
        overlay0: c(0x92_83_74),
        surface2: c(0x66_5c_54),
        surface1: c(0x50_49_45),
        surface0: c(0x3c_38_36),
        base: c(0x28_28_28),
        mantle: c(0x1d_20_21),
        crust: c(0x1d_20_21),
    }
}

/// Builds an RGB color from a hex literal (used by the palette constants).
const fn c(value: u32) -> Color {
    Color::Rgb(
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    )
}

impl SofkaPalette {
    /// Maps sofka swatches onto our semantic roles (k9s-style: title=teal,
    /// selected row on a surface swatch, status colors from the accent group).
    #[must_use]
    pub const fn to_theme(&self) -> Theme {
        Theme {
            border: self.mauve,
            title: self.teal,
            dir_fg: self.blue,
            leaf_fg: self.text,
            selected_bg: self.surface2,
            selected_fg: self.text,
            masked_fg: self.overlay0,
            revealed_fg: self.green,
            status_error: self.red,
            status_warn: self.yellow,
            status_info: self.sky,
            status_success: self.green,
            editor_border: self.green,
        }
    }
}

/// Semantic color palette consumed by every view renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Default widget border color.
    pub border: Color,
    /// Widget title color.
    pub title: Color,
    /// Directory entries in the secrets browser.
    pub dir_fg: Color,
    /// Leaf (secret) entries in the browser.
    pub leaf_fg: Color,
    /// Background of the highlighted list row.
    pub selected_bg: Color,
    /// Foreground of the highlighted list row.
    pub selected_fg: Color,
    /// Masked (hidden) secret value color.
    pub masked_fg: Color,
    /// Revealed secret value color.
    pub revealed_fg: Color,
    /// Status line — error kind.
    pub status_error: Color,
    /// Status line — warning kind.
    pub status_warn: Color,
    /// Status line — informational kind.
    pub status_info: Color,
    /// Status line — success kind.
    pub status_success: Color,
    /// Edit-mode textarea border.
    pub editor_border: Color,
}

impl Default for Theme {
    fn default() -> Self {
        catppuccin_mocha().to_theme()
    }
}

impl Theme {
    /// Loads the theme from a sofka config when one exists (graceful fallback
    /// to the bundled default — sofka's catppuccin-mocha — when the config or
    /// skin is missing or unparsable). See [`crate::sofka::load_theme`].
    #[must_use]
    pub fn load_sofka_or_default() -> Self {
        crate::sofka::load_theme().unwrap_or_else(|| {
            tracing::debug!("no sofka theme found; using the bundled default");
            Self::default()
        })
    }
}
