/// Simple CPU count detection for configuration defaults
#[allow(dead_code)]
pub fn get() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
