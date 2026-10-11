//! Session debug NDJSON logger (debug-mode instrumentation).

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_PATH: &str = "/Users/francoisegner/Desktop/bitwarden-tui/.cursor/debug-cc48b8.log";
const SESSION_ID: &str = "cc48b8";

static LOCK: Mutex<()> = Mutex::new(());

pub fn log(hypothesis_id: &str, location: &str, message: &str, data: serde_json::Value) {
    // #region agent log
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let payload = serde_json::json!({
        "sessionId": SESSION_ID,
        "runId": std::env::var("DEBUG_RUN_ID").unwrap_or_else(|_| "pre-fix".into()),
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": ts,
    });
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG_PATH) {
        let _ = writeln!(f, "{payload}");
        let _ = f.flush();
    }
    // #endregion
}
