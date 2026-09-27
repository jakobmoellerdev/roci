//! Dirfd-anchored, no-follow filesystem primitives beneath the store root
//! (SECURITY.md inv. 8).

use std::io;
use std::path::Path;

#[cfg(unix)]
use crate::publish::promote_temp_noreplace;

/// Run blocking filesystem work on tokio's blocking pool, entering the caller's
/// span and recording a hop metric.
pub(crate) async fn run_blocking<T, F>(op: &'static str, f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    roci_telemetry::record_blocking_hop(op);
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _guard = span.enter();
        f()
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(unix)]
fn open_root(root: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// Linux ≥ 5.6 fast path: one `openat2(RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS)`
/// call instead of a per-component walk. `None` when unavailable (old kernel / seccomp).
#[cfg(target_os = "linux")]
fn openat2_beneath(
    dir: &std::os::fd::OwnedFd,
    rel: &Path,
    flags: rustix::fs::OFlags,
) -> Option<io::Result<std::os::fd::OwnedFd>> {
    use rustix::fs::{Mode, ResolveFlags};
    use rustix::io::Errno;
    if fault!(FORCE_NO_OPENAT2) || rel.as_os_str().is_empty() {
        return None;
    }
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    // `openat2` rejects a non-zero mode without O_CREAT/O_TMPFILE.
    let mode = if flags.contains(rustix::fs::OFlags::CREATE)
        || flags.contains(rustix::fs::OFlags::TMPFILE)
    {
        Mode::from_raw_mode(0o644)
    } else {
        Mode::empty()
    };
    match rustix::fs::openat2(dir, rel, flags, mode, resolve) {
        Ok(fd) => Some(Ok(fd)),
        Err(Errno::NOSYS | Errno::PERM) => None,
        Err(Errno::LOOP | Errno::NOTDIR | Errno::XDEV) => {
            Some(Err(io::Error::from(io::ErrorKind::NotFound)))
        }
        Err(e) => Some(Err(io::Error::from(e))),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn openat2_beneath(
    _dir: &std::os::fd::OwnedFd,
    _rel: &Path,
    _flags: rustix::fs::OFlags,
) -> Option<io::Result<std::os::fd::OwnedFd>> {
    None
}

pub(crate) async fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        tokio::fs::File::open(dir).await?.sync_all().await
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Walk `rel` component-by-component with `openat(O_NOFOLLOW)`, refusing symlinks
/// at every level, and open the final component with `final_flags`.
/// Symlink at any component → `NotFound`.
#[cfg(unix)]
pub(crate) fn resolve_beneath(
    root: &Path,
    rel: &Path,
    final_flags: rustix::fs::OFlags,
) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    // Store root is trusted; O_NONBLOCK prevents blocking on planted FIFOs.
    let mut dir: OwnedFd = open_root(root)?;
    let leaf_flags = final_flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if let Some(opened) = openat2_beneath(&dir, rel, leaf_flags) {
        dir = opened?;
        return regular_file(dir);
    }

    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let flags = if last {
            leaf_flags
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let next = match rustix::fs::openat(&dir, *comp, flags, Mode::from_raw_mode(0o644)) {
            Ok(fd) => fd,
            // Symlink at any component → NotFound (never follows out-of-store).
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        };
        dir = next;
    }
    regular_file(dir)
}

#[cfg(unix)]
fn regular_file(fd: std::os::fd::OwnedFd) -> io::Result<std::fs::File> {
    use rustix::fs::FileType;
    let st = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    Ok(std::fs::File::from(fd))
}

/// Walk a directory path `rel` component-by-component with `O_DIRECTORY | O_NOFOLLOW`,
/// creating missing components when `create`. Returns an owned fd for the leaf
/// directory — callers anchor mutations relative to it so a symlinked parent
/// cannot redirect operations outside the store.
#[cfg(unix)]
pub(crate) fn dir_beneath(
    root: &Path,
    rel: &Path,
    create: bool,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir: OwnedFd = open_root(root)?;
    if !fault!(FORCE_SYSCALL_ERROR) {
        match openat2_beneath(&dir, rel, dir_flags) {
            Some(Ok(fd)) => return Ok(fd),
            Some(Err(e)) if create && e.kind() == io::ErrorKind::NotFound => {}
            Some(Err(e)) => return Err(e),
            None => {}
        }
    }
    for comp in rel.iter() {
        let opened = if fault!(FORCE_SYSCALL_ERROR) {
            Err(rustix::io::Errno::IO)
        } else {
            rustix::fs::openat(&dir, comp, dir_flags, Mode::empty())
        };
        match opened {
            Ok(next) => dir = next,
            Err(rustix::io::Errno::NOENT) if create => {
                // Create missing dir then open no-follow; concurrent EEXIST is fine.
                match rustix::fs::mkdirat(&dir, comp, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(io::Error::from(e)),
                }
                // Re-open no-follow: a racer replacing the dir with a
                // symlink/non-dir is normalized to NotFound.
                dir = match rustix::fs::openat(&dir, comp, dir_flags, Mode::empty()) {
                    Ok(next) => next,
                    Err(
                        rustix::io::Errno::LOOP
                        | rustix::io::Errno::NOTDIR
                        | rustix::io::Errno::NOENT,
                    ) => return Err(io::Error::from(io::ErrorKind::NotFound)),
                    Err(e) => return Err(io::Error::from(e)),
                };
            }
            // Symlinked/non-directory/missing component → NotFound.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NOENT) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    Ok(dir)
}

/// Rename `from_leaf` → `to_leaf` via dirfds walked no-follow beneath `root`.
/// `expected_ino` binds the promotion to the hashed inode: a raced swap
/// between hash and rename is rejected as `NotFound` (SECURITY: TOCTOU defence).
#[cfg(unix)]
pub(crate) fn rename_beneath_sync(
    root: std::path::PathBuf,
    from_dir_rel: std::path::PathBuf,
    from_leaf: String,
    to_dir_rel: std::path::PathBuf,
    to_leaf: String,
    expected_ino: (u64, u64),
    sync: bool,
) -> io::Result<()> {
    use rustix::fs::AtFlags;

    let from_fd = dir_beneath(&root, &from_dir_rel, false)?;
    let to_fd = dir_beneath(&root, &to_dir_rel, true)?;
    // Verify source inode matches what we hashed (TOCTOU defence).
    let st = rustix::fs::statat(&from_fd, from_leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if (st.st_dev as u64, st.st_ino as u64) != expected_ino {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    // NOREPLACE: EEXIST accepted only if destination is a regular file.
    use rustix::fs::{FileType, RenameFlags};
    match rustix::fs::renameat_with(
        &from_fd,
        from_leaf.as_str(),
        &to_fd,
        to_leaf.as_str(),
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            if sync {
                rustix::fs::fsync(&to_fd).map_err(io::Error::from)?;
            }
            Ok(())
        }
        Err(rustix::io::Errno::EXIST) => {
            let dst = rustix::fs::statat(&to_fd, to_leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
            if FileType::from_raw_mode(dst.st_mode).is_file() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CAS destination exists and is not a regular file",
                ))
            }
        }
        Err(e) => Err(io::Error::from(e)),
    }
}

#[cfg(unix)]
pub async fn unlink_beneath(root: &Path, dir_rel: &Path, leaf: &str) -> io::Result<()> {
    let root = root.to_path_buf();
    let dir_rel = dir_rel.to_path_buf();
    let leaf = leaf.to_string();
    run_blocking("unlink_beneath", move || {
        unlink_beneath_sync(root, dir_rel, leaf)
    })
    .await
}

#[cfg(unix)]
pub(crate) fn unlink_beneath_sync(
    root: std::path::PathBuf,
    dir_rel: std::path::PathBuf,
    leaf: String,
) -> io::Result<()> {
    let dirfd = dir_beneath(&root, &dir_rel, false)?;
    rustix::fs::unlinkat(&dirfd, leaf.as_str(), rustix::fs::AtFlags::empty())
        .map_err(io::Error::from)
}

/// Create an empty file `leaf` inside `dir_rel` via a no-follow dirfd beneath
/// `root`, creating the directory tree.
#[cfg(unix)]
pub async fn create_empty_beneath(root: &Path, dir_rel: &Path, leaf: &str) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    let root = root.to_path_buf();
    let dir_rel = dir_rel.to_path_buf();
    let leaf = leaf.to_string();
    run_blocking("create_empty_beneath", move || -> io::Result<()> {
        let dirfd = dir_beneath(&root, &dir_rel, true)?;
        let fd = rustix::fs::openat(
            &dirfd,
            leaf.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(io::Error::from)?;
        drop(std::fs::File::from(fd));
        Ok(())
    })
    .await
}

/// Ensure `<repo…>` has a valid `oci-layout` marker, anchored no-follow beneath
/// `root`. Idempotent. Returns whether the marker was newly written.
#[cfg(unix)]
pub(crate) async fn ensure_layout_beneath(
    root: &Path,
    repo_rel: &Path,
    marker: &str,
) -> io::Result<bool> {
    let root = root.to_path_buf();
    let repo_rel = repo_rel.to_path_buf();
    let marker = marker.to_string();
    run_blocking("ensure_layout_beneath", move || {
        ensure_layout_beneath_sync(root, repo_rel, marker)
    })
    .await
}

#[cfg(unix)]
pub(crate) fn ensure_layout_beneath_sync(
    root: std::path::PathBuf,
    repo_rel: std::path::PathBuf,
    marker: String,
) -> io::Result<bool> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    use std::io::Write as _;
    let dirfd = dir_beneath(&root, &repo_rel, true)?;
    // Idempotent: existing regular oci-layout is the steady state.
    match rustix::fs::statat(&dirfd, "oci-layout", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => return Ok(false),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "oci-layout exists and is not a regular file",
            ))
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(io::Error::from(e)),
    }
    // Write marker to a temp, fsync, then no-replace rename.
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(io::Error::other)?;
    let tmp = format!(".oci-layout.{}.tmp", hex::encode(rnd));
    let fd = rustix::fs::openat(
        &dirfd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .map_err(io::Error::from)?;
    let mut f = std::fs::File::from(fd);
    f.write_all(marker.as_bytes())?;
    f.sync_all()?;
    drop(f);
    // Concurrent creator winning the race is idempotent success.
    promote_temp_noreplace(&dirfd, tmp.as_str(), "oci-layout", true).map(|()| true)
}

/// Open `rel` beneath `root` read-only, no-follow at every component.
#[cfg(unix)]
pub async fn open_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f = run_blocking("open_beneath", move || {
        resolve_beneath(&root, &rel, OFlags::RDONLY)
    })
    .await?;
    Ok(tokio::fs::File::from_std(f))
}

/// Open `rel` beneath `root` for appending, no-follow at every component.
#[cfg(unix)]
pub async fn open_append_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f = run_blocking("open_append_beneath", move || {
        resolve_beneath(&root, &rel, OFlags::WRONLY | OFlags::APPEND)
    })
    .await?;
    Ok(tokio::fs::File::from_std(f))
}

/// Stat a CAS entry beneath `root` with no symlink traversal:
/// `Some((is_regular_file, size))` or `None` if absent.
#[cfg(unix)]
pub async fn stat_beneath(root: &Path, rel: &Path) -> io::Result<Option<(bool, u64)>> {
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    run_blocking("stat_beneath", move || stat_beneath_sync(root, rel)).await
}

#[cfg(unix)]
pub(crate) fn stat_beneath_sync(
    root: std::path::PathBuf,
    rel: std::path::PathBuf,
) -> io::Result<Option<(bool, u64)>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    // Walk to the parent no-follow, then stat the leaf.
    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    let Some((last, parents)) = comps.split_last() else {
        return Ok(None);
    };
    let mut dir = open_root(&root)?;
    for comp in parents {
        match rustix::fs::openat(
            &dir,
            *comp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => dir = next,
            // Missing/symlinked/non-dir parent → absent (not error).
            // EACCES is NOT swallowed — surfaces as 500, not false 404.
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                return Ok(None)
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    // Stat the leaf no-follow; FORCE_STAT_ERROR injects a fault in tests.
    let statted = if fault!(FORCE_STAT_ERROR) {
        Err(rustix::io::Errno::IO)
    } else {
        rustix::fs::statat(&dir, *last, AtFlags::SYMLINK_NOFOLLOW)
    };
    match statted {
        Ok(st) => Ok(Some((
            FileType::from_raw_mode(st.st_mode).is_file(),
            st.st_size as u64,
        ))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(io::Error::from(e)),
    }
}
