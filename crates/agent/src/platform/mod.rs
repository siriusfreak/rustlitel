//! OS-specific install/uninstall/service plumbing. Real on Windows; stubs
//! elsewhere so the binary still builds and runs in the foreground.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{apply_update, install, run_service, self_uninstall, uninstall};

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub use other::{apply_update, install, run_service, self_uninstall, uninstall};
