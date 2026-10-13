//! Clipboard adapters for copying selected secret values.

use std::fmt;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use copypasta::ClipboardProvider as _;

/// A text clipboard the app can write to.
pub trait TextClipboard: Send + Sync {
    /// Copies text into the clipboard.
    fn copy(&self, text: &str) -> Result<(), ClipboardError>;
}

/// Surface-level clipboard errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClipboardError {
    /// No usable clipboard backend is available.
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
    /// A clipboard backend was found, but writing text failed.
    #[error("clipboard write failed: {0}")]
    WriteFailed(String),
}

/// OS-level clipboard via the copypasta crate.
#[non_exhaustive]
pub struct SystemClipboard {
    inner: Mutex<copypasta::ClipboardContext>,
}

impl fmt::Debug for SystemClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemClipboard").finish_non_exhaustive()
    }
}

impl SystemClipboard {
    /// Builds a system clipboard adapter.
    pub fn new() -> Result<Self, ClipboardError> {
        copypasta::ClipboardContext::new()
            .map(|inner| Self {
                inner: Mutex::new(inner),
            })
            .map_err(|err| ClipboardError::Unavailable(err.to_string()))
    }
}

impl TextClipboard for SystemClipboard {
    fn copy(&self, text: &str) -> Result<(), ClipboardError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|err| ClipboardError::Unavailable(err.to_string()))?;
        inner
            .set_contents(text.to_owned())
            .map_err(|err| ClipboardError::WriteFailed(err.to_string()))
    }
}

/// Clipboard backed by an external command that reads text on stdin.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommandClipboard {
    program: PathBuf,
    args: Vec<String>,
}

impl CommandClipboard {
    /// Builds a command clipboard adapter.
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }
}

impl TextClipboard for CommandClipboard {
    fn copy(&self, text: &str) -> Result<(), ClipboardError> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| ClipboardError::Unavailable(err.to_string()))?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            ClipboardError::WriteFailed(format!("{} did not open stdin", self.program.display()))
        })?;
        stdin
            .write_all(text.as_bytes())
            .map_err(|err| ClipboardError::WriteFailed(err.to_string()))?;
        drop(stdin);

        let status = child
            .wait()
            .map_err(|err| ClipboardError::WriteFailed(err.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(ClipboardError::WriteFailed(format!(
                "{} exited with {status}",
                self.program.display()
            )))
        }
    }
}

/// Builds the best clipboard for the current platform.
pub fn default_clipboard() -> Box<dyn TextClipboard> {
    match SystemClipboard::new() {
        Ok(clipboard) => Box::new(clipboard),
        Err(error) => command_fallback().map_or_else(
            || Box::new(UnavailableClipboard { error }) as Box<dyn TextClipboard>,
            |clipboard| Box::new(clipboard) as Box<dyn TextClipboard>,
        ),
    }
}

#[derive(Debug)]
struct UnavailableClipboard {
    error: ClipboardError,
}

impl TextClipboard for UnavailableClipboard {
    fn copy(&self, _text: &str) -> Result<(), ClipboardError> {
        Err(ClipboardError::Unavailable(self.error.to_string()))
    }
}

#[cfg(target_os = "macos")]
fn command_fallback() -> Option<CommandClipboard> {
    command_exists("pbcopy").then(|| CommandClipboard::new("pbcopy", Vec::new()))
}

#[cfg(target_os = "linux")]
fn command_fallback() -> Option<CommandClipboard> {
    if command_exists("xclip") {
        Some(CommandClipboard::new(
            "xclip",
            vec!["-selection".to_owned(), "clipboard".to_owned()],
        ))
    } else if command_exists("wl-copy") {
        Some(CommandClipboard::new("wl-copy", Vec::new()))
    } else {
        None
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn command_fallback() -> Option<CommandClipboard> {
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{ClipboardError, CommandClipboard, TextClipboard, default_clipboard};

    #[cfg(unix)]
    fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let script = dir.join(name);
        fs::write(&script, body).expect("script should be writable");
        let mut permissions = fs::metadata(&script)
            .expect("script metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("script should be executable");
        script
    }

    #[cfg(unix)]
    #[test]
    fn test_command_clipboard_writes_exact_text_when_program_exits_successfully() {
        // Given: a command clipboard backed by a script that writes stdin to its first arg.
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let output_path = temp_dir.path().join("clipboard.txt");
        let script =
            write_executable_script(temp_dir.path(), "copy-ok.sh", "#!/bin/sh\ncat > \"$1\"\n");
        let clipboard = CommandClipboard::new(script, vec![output_path.display().to_string()]);
        let text = "top\nsecret=42";

        // When: text is copied through the command clipboard.
        clipboard.copy(text).expect("copy should succeed");

        // Then: the subprocess receives exactly the supplied text.
        let copied = fs::read_to_string(output_path).expect("copied text should be readable");
        assert_eq!(copied, text);
    }

    #[cfg(unix)]
    #[test]
    fn test_command_clipboard_returns_write_failed_when_program_exits_nonzero() {
        // Given: a command clipboard backed by a script that exits with failure.
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let script =
            write_executable_script(temp_dir.path(), "copy-fail.sh", "#!/bin/sh\nexit 1\n");
        let clipboard = CommandClipboard::new(script, Vec::new());

        // When: text is copied through the command clipboard.
        let result = clipboard.copy("secret");

        // Then: the failure is surfaced as a write failure.
        assert!(matches!(result, Err(ClipboardError::WriteFailed(_))));
    }

    #[test]
    fn test_default_clipboard_constructs_when_called_on_current_platform() {
        // Given: the current platform clipboard environment.

        // When: the default clipboard is constructed.
        let _clipboard = default_clipboard();

        // Then: construction returns a clipboard object without writing user clipboard data.
    }
}
