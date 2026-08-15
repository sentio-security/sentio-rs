//! Read Cargo profile settings relevant to static analysis.
//!
//! Used so rules do not claim "wraps in release" when the package already enables
//! panic-on-overflow for release builds.

use std::path::{Path, PathBuf};

/// Walk from `start` (file or directory) upward and return the nearest explicit
/// `[profile.release] overflow-checks` setting.
///
/// Cargo merges workspace → package; a closer `Cargo.toml` that sets the key wins.
/// If no ancestor sets it, returns `false` (Rust default for release is off).
pub fn release_overflow_checks_enabled(start: &Path) -> bool {
    for dir in ancestors_of(start) {
        let cargo_toml = dir.join("Cargo.toml");
        if !cargo_toml.is_file() {
            continue;
        }
        if let Some(value) = read_release_overflow_checks(&cargo_toml) {
            return value;
        }
    }
    false
}

fn ancestors_of(start: &Path) -> Vec<PathBuf> {
    let start = if start.is_file() {
        start
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| start.to_path_buf())
    } else {
        start.to_path_buf()
    };
    start.ancestors().map(Path::to_path_buf).collect()
}

/// `Some(bool)` if `profile.release.overflow-checks` is present; `None` if unset/unreadable.
pub fn read_release_overflow_checks(cargo_toml: &Path) -> Option<bool> {
    let content = std::fs::read_to_string(cargo_toml).ok()?;
    // Prefer `toml::Table` parse for toml 1.x compatibility.
    let value: toml::Value = toml::from_str(&content).ok()?;
    value
        .get("profile")?
        .get("release")?
        .get("overflow-checks")?
        .as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sentio-overflow-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detects_overflow_checks_true() {
        let dir = temp_dir();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        let file = src.join("lib.rs");
        fs::write(&file, "fn main() {}").unwrap();

        assert!(
            release_overflow_checks_enabled(&file),
            "expected overflow-checks=true from {:?}",
            dir.join("Cargo.toml")
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn detects_overflow_checks_false() {
        let dir = temp_dir();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[profile.release]\noverflow-checks = false\n",
        )
        .unwrap();
        assert!(!release_overflow_checks_enabled(&dir));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn defaults_false_when_unset() {
        let dir = temp_dir();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert!(!release_overflow_checks_enabled(&dir));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn nearer_package_overrides_workspace() {
        let root = temp_dir();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"prog\"]\n\n[profile.release]\noverflow-checks = false\n",
        )
        .unwrap();
        let prog = root.join("prog");
        fs::create_dir_all(prog.join("src")).unwrap();
        fs::write(
            prog.join("Cargo.toml"),
            "[package]\nname = \"prog\"\nversion = \"0.1.0\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        let file = prog.join("src/lib.rs");
        fs::write(&file, "").unwrap();

        assert!(release_overflow_checks_enabled(&file));
        fs::remove_dir_all(root).ok();
    }
}
