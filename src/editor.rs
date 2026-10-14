//! External text editor handoff for policy authoring.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

/// Buffer metadata and initial contents passed to a [`TextEditor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditBuffer {
    /// Initial text written to the temporary file.
    pub initial_text: String,
    /// Stem used for the temporary file name.
    pub file_stem: String,
    /// File suffix (including dot), e.g. `.hcl`.
    pub extension: &'static str,
}

/// Outcome returned by a [`TextEditor`] after editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOutcome {
    /// File contents were unchanged.
    Unchanged,
    /// File contents changed and are returned as UTF-8 text.
    Changed(String),
}

/// Synchronous text editor boundary used by the terminal handoff flow.
pub trait TextEditor: Send + Sync {
    /// Opens an editor for `buffer` and returns whether the text changed.
    fn edit(&self, buffer: &EditBuffer) -> Result<EditOutcome, EditorError>;
}

/// Command-based editor implementation (`$VISUAL`/`$EDITOR` value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTextEditor {
    command: String,
}

impl CommandTextEditor {
    /// Builds a command-based editor with the provided shell command.
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
        }
    }

    /// Builds the default editor from `$VISUAL`, then `$EDITOR`.
    ///
    /// # Errors
    /// Returns [`EditorError::MissingEditor`] when neither variable is set to a
    /// non-empty value.
    pub fn default_editor() -> Result<Self, EditorError> {
        std::env::var("VISUAL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                std::env::var("EDITOR")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            })
            .map(Self::new)
            .ok_or(EditorError::MissingEditor)
    }

    fn invoke_command(&self, file_path: &Path) -> Result<ExitStatus, EditorError> {
        #[cfg(unix)]
        {
            Command::new("sh")
                .arg("-c")
                .arg(format!("{} \"$1\"", self.command))
                .arg("sh")
                .arg(file_path)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|err| EditorError::Command(err.to_string()))
        }
        #[cfg(windows)]
        {
            Command::new("cmd")
                .arg("/C")
                .arg(&self.command)
                .arg(file_path)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|err| EditorError::Command(err.to_string()))
        }
    }
}

impl TextEditor for CommandTextEditor {
    fn edit(&self, buffer: &EditBuffer) -> Result<EditOutcome, EditorError> {
        let mut temp_file = tempfile::Builder::new()
            .prefix(&buffer.file_stem)
            .suffix(buffer.extension)
            .tempfile()
            .map_err(|err| EditorError::TempFile(err.to_string()))?;
        temp_file
            .write_all(buffer.initial_text.as_bytes())
            .map_err(|err| EditorError::TempFile(err.to_string()))?;
        temp_file
            .flush()
            .map_err(|err| EditorError::TempFile(err.to_string()))?;

        let status = self.invoke_command(temp_file.path())?;
        if !status.success() {
            return Err(EditorError::ExitStatus(status));
        }

        let updated = std::fs::read_to_string(temp_file.path())
            .map_err(|err| EditorError::TempFile(err.to_string()))?;
        if updated == buffer.initial_text {
            Ok(EditOutcome::Unchanged)
        } else {
            Ok(EditOutcome::Changed(updated))
        }
    }
}

/// User-facing editor handoff errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EditorError {
    /// Neither `$VISUAL` nor `$EDITOR` is configured.
    #[error("no editor configured: set `VISUAL` or `EDITOR`")]
    MissingEditor,
    /// Temporary file creation/read/write failed.
    #[error("temporary file error: {0}")]
    TempFile(String),
    /// Editor command launch failed.
    #[error("failed to run editor command: {0}")]
    Command(String),
    /// Editor process exited unsuccessfully.
    #[error("editor exited with status {0}")]
    ExitStatus(ExitStatus),
    /// Editor execution panicked and was caught by the terminal owner.
    #[error("editor handoff panicked")]
    Panicked,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use direct fixture assertions"
)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{CommandTextEditor, EditBuffer, EditOutcome, EditorError, TextEditor};

    #[cfg(unix)]
    fn write_executable_script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
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
    fn command_editor_returns_changed_when_script_appends_text() {
        // Given: an editor command that appends one line to the temp file.
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let script = write_executable_script(
            temp_dir.path(),
            "append.sh",
            "#!/bin/sh\nprintf '\nappend' >> \"$1\"\n",
        );
        let editor = CommandTextEditor::new(script.display().to_string());
        let buffer = EditBuffer {
            initial_text: "base".to_owned(),
            file_stem: "policy".to_owned(),
            extension: ".hcl",
        };

        // When: editing is executed.
        let result = editor.edit(&buffer).expect("edit should succeed");

        // Then: the updated text is surfaced as changed.
        assert_eq!(result, EditOutcome::Changed("base\nappend".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn command_editor_returns_exit_status_for_nonzero_exit() {
        // Given: an editor command that exits with failure.
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let script = write_executable_script(temp_dir.path(), "fail.sh", "#!/bin/sh\nexit 2\n");
        let editor = CommandTextEditor::new(script.display().to_string());
        let buffer = EditBuffer {
            initial_text: "base".to_owned(),
            file_stem: "policy".to_owned(),
            extension: ".hcl",
        };

        // When: editing is executed.
        let result = editor.edit(&buffer);

        // Then: nonzero exits map to `ExitStatus`.
        assert!(matches!(result, Err(EditorError::ExitStatus(_))));
    }
}
