use std::sync::{atomic::AtomicBool, Arc};
/// Install the shared stop flag before announcing solver readiness.
pub(crate) fn install(stop: Arc<AtomicBool>) -> std::io::Result<()> {
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop)?;
    Ok(())
}
