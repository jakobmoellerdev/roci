//! Test-only fault-injection switches (Linux only): process-global flags the
//! fault tests flip to drive otherwise-unreachable syscall-error and
//! copy/reflink-fallback arms deterministically on CI's single filesystem.

/// `fault!(FORCE_X)`: whether the test-only fault switch is set; constant
/// `false` outside `cfg(all(test, target_os = "linux"))`, so release builds
/// carry no seam.
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

/// Test-only switches: on a single filesystem a real `ioctl_ficlone`/`hard_link`
/// neither fails (to exercise the copy fallback) nor succeeds (ext4 has no
/// reflink), so both branches are otherwise unreachable. `FORCE_COPY_FALLBACK`
/// makes the fast paths report failure; `FORCE_REFLINK_OK` makes `try_reflink`
/// report success (after really transferring the bytes via the streaming copy,
/// so the destination is correct). Zero cost and absent outside `cfg(test)`.
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

/// Serializes the fault-injection tests (which flip the process-global
/// `FORCE_*` switches) against each other and against tests that assert on the
/// real reflink/hard-link behavior, so a stray forced fallback cannot make a
/// parallel test flaky. Held for the duration of each such test.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static FAULT_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
