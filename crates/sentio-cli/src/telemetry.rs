//! Lightweight version-check ping, fired only by `sentio version`.
//!
//! This intentionally does not run on `sentio scan` or any other command —
//! it only fires when the user explicitly asks to check their installed
//! version, which keeps the behavior predictable and opt-in by usage.

const NO_TELEMETRY_ENV: &str = "SENTIO_NO_TELEMETRY";

/// Endpoint that receives version-check pings.
const PING_ENDPOINT: Option<&str> = Some("https://sentiosecurity.xyz/api/version-check");

pub struct VersionCheck {
    pub latest: Option<String>,
}

/// Pings the version-check endpoint with the installed version. Best-effort:
/// network errors, timeouts, and a missing endpoint are all silently
/// swallowed so this can never break the `version` command.
pub fn check_version(installed: &str) -> VersionCheck {
    if std::env::var(NO_TELEMETRY_ENV).is_ok() {
        return VersionCheck { latest: None };
    }

    let Some(endpoint) = PING_ENDPOINT else {
        return VersionCheck { latest: None };
    };

    let latest = ureq::get(endpoint)
        .query("version", installed)
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
