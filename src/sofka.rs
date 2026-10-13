//! Sofka theme reuse.
//!
//! Reads sofka's configuration (`~/.config/sofka/config.toml` plus
//! `conf.d/*.toml` drop-ins) and maps its `[skin]` (name + `colors`
//! overrides) onto our [`Theme`]. Graceful: a missing or unparsable config
//! yields `None` so callers fall back to the bundled default.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ratatui::style::Color;
use serde::Deserialize;

use crate::theme::{SofkaPalette, Theme, sofka_skin};

/// Reads a theme from sofka's config on this machine.
#[must_use]
pub fn load_theme() -> Option<Theme> {
    let paths = sofka_config_paths()?;
    resolve_theme(&paths)
}

/// The candidate sofka config files in sofka's own precedence order: base
/// `config.toml`, then sorted `conf.d/*.toml` drop-ins merged over it.
pub fn sofka_config_paths() -> Option<Vec<PathBuf>> {
    let config_dir = config_dir()?;
    let mut paths = Vec::new();
    let base = config_dir.join("config.toml");
    if base.is_file() {
        paths.push(base);
    }
    let dropins = config_dir.join("conf.d");
    if dropins.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dropins)
            .ok()?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        entries.sort();
        paths.extend(entries);
    }
    Some(paths)
}

fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("SOFKA_CONFIG") {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").join("sofka"))
}

/// Resolves `[skin]` from the given config files, applying later-file overrides.
pub fn resolve_theme(paths: &[PathBuf]) -> Option<Theme> {
    let mut skin = SkinConfig::default();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        match parse_skin_file(path) {
            Ok(Some(found)) => skin = skin.overlay_with(found),
            Ok(None) => {}
            Err(err) => tracing::warn!(?path, %err, "ignoring unparsable sofka config"),
        }
    }
    if !skin.any() {
        return None;
    }
    let palette = resolve_palette(&skin);
    let mut theme = palette.to_theme();
    apply_color_overrides(&mut theme, &skin.colors);
    Some(theme)
}

/// The base config shape we care about (extra keys are ignored, matching how
/// sofka itself tolerates unknown sections in its own config).
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    skin: Option<SkinConfig>,
}

/// The `[skin]` section with per-swatch `[skin.colors]` overrides.
#[derive(Debug, Clone, Default, Deserialize)]
struct SkinConfig {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    colors: BTreeMap<String, String>,
}

impl SkinConfig {
    /// Later files win: `Some` fields from `other` replace ours.
    fn overlay_with(self, other: Self) -> Self {
        let mut merged = self;
        if other.name.is_some() {
            merged.name = other.name;
        }
        merged.colors.extend(other.colors);
        merged
    }

    fn any(&self) -> bool {
        self.name.is_some() || !self.colors.is_empty()
    }
}

fn parse_skin_file(path: &Path) -> Result<Option<SkinConfig>, toml::de::Error> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    let config: FileConfig = toml::from_str(&raw)?;
    Ok(config.skin)
}

/// Resolves the named (or default) palette for a `[skin]` entry.
fn resolve_palette(skin: &SkinConfig) -> SofkaPalette {
    skin.name
        .as_deref()
        .map_or_else(crate::theme::catppuccin_mocha, |name| {
            sofka_skin(name).unwrap_or_else(|| {
                tracing::warn!(
                    %name,
                    "sofka skin not bundled (catppuccin family + gruvbox-dark); using mocha"
                );
                crate::theme::catppuccin_mocha()
            })
        })
}

/// Applies `[skin.colors]` overrides to the semantically mapped theme fields.
fn apply_color_overrides(theme: &mut Theme, colors: &BTreeMap<String, String>) {
    for (swatch, hex) in colors {
        let Some(color) = parse_hex(hex) else {
            tracing::warn!(%swatch, %hex, "ignoring invalid sofka swatch color");
            continue;
        };
        match swatch.as_str() {
            "red" => theme.status_error = color,
            "yellow" => theme.status_warn = color,
            "green" => {
                theme.revealed_fg = color;
                theme.status_success = color;
                theme.editor_border = color;
            }
            "sky" => theme.status_info = color,
            "mauve" => theme.border = color,
            "teal" => theme.title = color,
            "blue" => theme.dir_fg = color,
            "text" => {
                theme.leaf_fg = color;
                theme.selected_fg = color;
            }
            "surface0" => theme.selected_bg = color,
            "overlay0" => theme.masked_fg = color,
            _ => {} // swatches our roles do not consume
        }
    }
}

/// Parses `#rrggbb` (case-insensitive, `#` optional — sofka's hex rules).
fn parse_hex(raw: &str) -> Option<Color> {
    let hex = raw.trim().strip_prefix('#').unwrap_or_else(|| raw.trim());
    if hex.len() != 6 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(Color::Rgb(
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env_lock;
    use crate::theme::catppuccin_mocha;

    fn dir_with(path: &Path, name: &str, content: &str) -> PathBuf {
        std::fs::create_dir_all(path).expect("fixture dir");
        let file = path.join(name);
        std::fs::write(&file, content).expect("fixture file");
        file
    }

    #[test]
    fn test_resolve_theme_when_no_config_present_returns_none() {
        // Given: no config files at all.
        // When: resolution runs over an empty set.
        let theme = resolve_theme(&[]);
        // Then: nothing to load (caller falls back to the default).
        assert_eq!(theme, None);
    }

    #[test]
    fn test_resolve_theme_applies_named_skin_and_overrides() {
        // Given: a sofka-style config selecting gruvbox-dark with a swatch override.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir_with(
            dir.path(),
            "config.toml",
            r##"
            [skin]
            name = "gruvbox-dark"
            [skin.colors]
            red = "#ff0000"
            teal = "#00ffff"
            "##,
        );

        // When: the theme is resolved.
        let theme = resolve_theme(std::slice::from_ref(&config)).expect("theme");

        // Then: the skin's palette is mapped and the overrides win.
        assert_eq!(theme.border, crate::theme::gruvbox_dark().mauve);
        assert_eq!(theme.title, Color::Rgb(0x00, 0xff, 0xff));
        assert_eq!(theme.status_error, Color::Rgb(0xff, 0x00, 0x00));
        assert_eq!(theme.status_success, crate::theme::gruvbox_dark().green);
    }

    #[test]
    fn test_resolve_theme_merges_dropins_over_base() {
        // Given: a base config and a later conf.d drop-in that overrides a swatch.
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir_with(
            dir.path(),
            "base.toml",
            "[skin]\nname = \"mocha\"\n[skin.colors]\nred = \"#111111\"\n",
        );
        let dropin = dir_with(
            dir.path(),
            "20-later.toml",
            "[skin.colors]\nred = \"#ff0000\"\n",
        );

        // When: both files are resolved in order.
        let theme = resolve_theme(&[base, dropin]).expect("theme");

        // Then: the drop-in override wins over the base file.
        assert_eq!(theme.status_error, Color::Rgb(0xff, 0x00, 0x00));
        assert_eq!(theme.title, catppuccin_mocha().teal);
    }

    #[test]
    fn test_resolve_theme_unknown_skin_falls_back_to_mocha() {
        // Given: a config naming a skin we do not bundle.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir_with(dir.path(), "config.toml", "[skin]\nname = \"nord\"\n");

        // When: the theme is resolved.
        let theme = resolve_theme(std::slice::from_ref(&config)).expect("theme");

        // Then: the bundled mocha default is used (with a warning).
        assert_eq!(theme.border, catppuccin_mocha().mauve);
    }

    #[test]
    fn test_resolve_theme_unparsable_file_ignored() {
        // Given: a malformed config file.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir_with(dir.path(), "config.toml", "[skin\nname = broken");

        // When: the theme is resolved.
        let theme = resolve_theme(std::slice::from_ref(&config));

        // Then: the parse error is tolerated (graceful degradation).
        assert_eq!(theme, None);
    }

    #[test]
    fn test_parse_hex_variants() {
        // Given: sofka's accepted hex spellings.
        // When: each is parsed.
        // Then: `#rrggbb`, bare rrggbb, and case-insensitive values all map.
        assert_eq!(parse_hex("#ff0000"), Some(Color::Rgb(0xff, 0x00, 0x00)));
        assert_eq!(parse_hex("00FF00"), Some(Color::Rgb(0x00, 0xff, 0x00)));
        assert_eq!(parse_hex("zz0000"), None);
        assert_eq!(parse_hex("#fff"), None);
    }

    #[test]
    fn test_load_theme_uses_sofka_config_env_override() {
        // Given: SOFKA_CONFIG points at a temp dir whose config selects gruvbox-dark.
        let _lock = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        dir_with(
            dir.path(),
            "config.toml",
            "[skin]\nname = \"gruvbox-dark\"\n",
        );
        // SAFETY: `env_lock` serializes all env mutations in this test module.
        unsafe { std::env::set_var("SOFKA_CONFIG", dir.path()) };

        // When: the theme is loaded through the public entry point.
        let theme = load_theme();

        // Then: the gruvbox palette is mapped (status_error = gruvbox red).
        // SAFETY: `env_lock` serializes all env mutations in this test module.
        unsafe { std::env::remove_var("SOFKA_CONFIG") };
        assert_eq!(
            theme.map(|theme| theme.status_error),
            Some(crate::theme::gruvbox_dark().red)
        );
    }
}
