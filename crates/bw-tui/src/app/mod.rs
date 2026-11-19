//! Application state machine for the Vaultwarden TUI.
//!
//! Split for maintainability:
//! - [`state`] — `App` struct and methods (auth, vault nav, overlays, tick)
//! - Future: `auth.rs`, `vault_nav.rs`, `clipboard.rs`, `forms.rs`, `tick.rs`

mod power;
mod state;

pub use power::*;
pub use state::*;
