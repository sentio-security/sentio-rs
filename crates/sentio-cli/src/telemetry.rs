//! Lightweight version-check ping, fired by `sentio version` / `sentio --version`.
//!
//! This intentionally does not run on `sentio scan` or any other command —
//! it only fires when the user explicitly checks their installed version.
//!
//! A random anonymous ID is persisted locally (no PII, no machine
//! fingerprinting) so the backend can dedupe repeated checks from the same
//! install into a single "unique machine" count rather than inflating on
//! every run. Set `SENTIO_NO_TELEMETRY=1` to disable the ping entirely.

const NO_TELEMETRY_ENV: &str = "SENTIO_NO_TELEMETRY";

/// Endpoint that receives version-check pings.
const PING_ENDPOINT: Option<&str> = Some("https://www.sentiosecurity.xyz/api/version-check");

pub struct VersionCheck {
    pub latest: Option<String>,
}

/// Pings the version-check endpoint with the installed version and a
/// persisted anonymous ID. Best-effort: network errors, timeouts, a missing
/// endpoint, or a failure to read/write the local ID file are all silently
/// swallowed so this can never break the `version` command.
pub fn check_version(installed: &str) -> VersionCheck {
    if std::env::var(NO_TELEMETRY_ENV).is_ok() {
        return VersionCheck { latest: None };
    }

    let Some(endpoint) = PING_ENDPOINT else {
        return VersionCheck { latest: None };
    };

    let mut request = ureq::get(endpoint).query("version", installed);
    if let Some(id) = telemetry_id() {
        request = request.query("id", &id);
    }

    let latest = request
        .timeout(std::time::Duration::from_secs(2))
        .call()
        .ok()
        .and_then(|response| response.into_json::<serde_json::Value>().ok())
        .and_then(|body| {
            body.get("latest")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });

    VersionCheck { latest }
}

/// Reads the persisted anonymous telemetry ID, generating and saving one on
/// first run. Returns `None` if the config directory can't be resolved or
/// written to — the ping still proceeds without an ID in that case.
fn telemetry_id() -> Option<String> {
    let path = dirs::config_dir()?.join("sentio").join("telemetry_id");

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    std::fs::write(&path, &id).ok()?;

    Some(id)
}
