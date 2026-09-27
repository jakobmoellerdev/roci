//! Test-only fault-injection switches (Linux only).

/// Constant `false` outside `cfg(all(test, target_os = "linux"))`.
macro_rules! fault {
    ($flag:ident) => {{
        #[cfg(all(test, target_os = "linux"))]
        {
            $crate::fault::$flag.load(std::sync::atomic::Ordering::Relaxed)
        }
        #[cfg(not(all(test, target_os = "linux")))]
        {
            false
        }
    }};
}

/// Exercise copy/reflink fallbacks on single-filesystem CI.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_COPY_FALLBACK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_REFLINK_OK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_TMPFILE_UNSUPPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_STAT_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_SYSCALL_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Force the portable per-component walk instead of `openat2`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static FORCE_NO_OPENAT2: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Serializes fault-injection tests against each other.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static FAULT_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
