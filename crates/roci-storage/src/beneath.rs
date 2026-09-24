//! No-follow, dirfd-anchored filesystem primitives beneath the store root
//! (SECURITY.md inv. 8): every path component is opened `O_NOFOLLOW` so a
//! planted symlink at any level cannot redirect an operation outside the CAS.

use std::io;
use std::path::Path;

#[cfg(unix)]
use crate::publish::promote_temp_noreplace;

/// Run blocking filesystem work on tokio's blocking pool, mapping a join
/// failure to `io::Error`.
pub(crate) async fn run_blocking<T, F>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(io::Error::other)?
}

/// Open the (trusted, roci-created) store root as a directory fd; followed,
/// unlike every component beneath it.
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

/// Fsync a directory so a prior `rename` into it is durable (the rename's
/// effect on the directory entry is not persisted by syncing the file alone).
/// On Unix this opens the directory and `fsync`s it; on platforms where a
/// directory handle cannot be synced this is a best-effort no-op.
pub(crate) async fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        // Opening a directory read-only and fsyncing it persists a prior rename
        // into it. The CAS dir was just created, so the open succeeds; any error
        // propagates through `?` into the caller's single error path.
        tokio::fs::File::open(dir).await?.sync_all().await
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Walk `rel` (a `/`-separated path relative to `root`) component by component
/// with `openat` + `O_NOFOLLOW`, refusing to traverse a symlink at *any* level,
/// and open the final component with `final_flags`. `root` is the store root —
/// created and owned by roci, so it is the trusted anchor; every component below
/// it (`<repo…>/blobs/<alg>/<hex>`, `<repo…>/uploads/<id>`) is opened no-follow
/// so a planted symlink anywhere in the path — not just the final component —
/// cannot redirect the open outside the CAS. Portable across every Unix and
/// kernel (no `openat2` dependency). Runs on the caller's blocking thread.
#[cfg(unix)]
pub(crate) fn resolve_beneath(
    root: &Path,
    rel: &Path,
    final_flags: rustix::fs::OFlags,
) -> io::Result<std::fs::File> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::os::fd::OwnedFd;
    // The store root is trusted (roci created it); open it followed.
    let mut dir: OwnedFd = open_root(root)?;

    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let flags = if last {
            // `O_NONBLOCK` so opening a planted FIFO/device does not block; we
            // fstat and reject any non-regular final entry below.
            final_flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let next = match rustix::fs::openat(&dir, *comp, flags, Mode::from_raw_mode(0o644)) {
            Ok(fd) => fd,
            // A symlink at any component (or a non-dir parent) is refused by
            // `O_NOFOLLOW`/`O_DIRECTORY`: `ELOOP` (Linux) / `ENOTDIR` (macOS/BSD).
            // Surface it as "not found" so a read/open returns 404, never an
            // out-of-store target.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        };
        dir = next;
    }
    // The final descriptor must be a *regular file*: a FIFO/device/socket at a
    // digest path is not a valid CAS blob and must never be served or appended
    // to (a FIFO read would block, a device would return non-CAS bytes).
    let st = rustix::fs::fstat(&dir).map_err(io::Error::from)?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    Ok(std::fs::File::from(dir))
}

/// Walk a *directory* path `rel` (relative to `root`) component by component
/// with `openat` + `O_DIRECTORY | O_NOFOLLOW`, refusing to traverse a symlink at
/// any level, and return an owned fd for the leaf directory. When `create`, a
/// missing component is `mkdirat`-created (then opened no-follow) so the whole
/// CAS directory tree is materialised beneath the trusted root — never through a
/// planted symlink. This is the write-side anchor: callers do `openat`/`linkat`/
/// `renameat`/`unlinkat` *relative to the returned fd*, so a symlinked `repo`,
/// `blobs`, or `<alg>` parent can never redirect a mutation outside the store.
#[cfg(unix)]
pub(crate) fn dir_beneath(
    root: &Path,
    rel: &Path,
    create: bool,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    // The store root is trusted (roci created it); open it followed.
    let mut dir: OwnedFd = open_root(root)?;
    for comp in rel.iter() {
        let opened = if fault!(FORCE_SYSCALL_ERROR) {
            Err(rustix::io::Errno::IO)
        } else {
            rustix::fs::openat(&dir, comp, dir_flags, Mode::empty())
        };
        match opened {
            Ok(next) => dir = next,
            Err(rustix::io::Errno::NOENT) if create => {
                // Create the missing directory component (0o755) then open it
                // no-follow. A concurrent creator racing us yields EEXIST, which
                // we treat as "already there" and re-open.
                match rustix::fs::mkdirat(&dir, comp, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(io::Error::from(e)),
                }
                // Re-open no-follow. A racer that replaced the just-created dir
                // with a symlink/non-dir (or removed it) yields LOOP/NOTDIR/NOENT
                // — normalize to NotFound (404), matching the walk arm below,
                // rather than surfacing a raw 500.
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
            // A symlinked / non-directory / missing component: not a valid CAS
            // directory. `NotFound` so a read returns 404; a write with
            // `create=false` likewise cannot proceed through it.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NOENT) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    Ok(dir)
}

/// Rename `from_leaf` in directory `from_dir_rel` to `to_leaf` in directory
/// `to_dir_rel` (both relative to `root`), via `renameat` on dirfds walked
/// no-follow beneath `root` (the destination dir is created). A symlinked parent
/// on either side cannot redirect the rename outside the store. Then fsyncs the
/// destination directory so the new entry is durable.
///
/// `expected_ino` is the `(st_dev, st_ino)` of the inode the caller already
/// hashed+verified. Because `renameat` is name-based, a hostile local
/// filesystem actor could swap `from_leaf` for a different inode between the
/// hash and this call, promoting unverified bytes under the verified digest
/// name. We `statat` the source leaf no-follow and require the same inode
/// before renaming — binding the promotion to the hashed inode. A mismatch
/// (the leaf was swapped) is rejected as `NotFound` so the upload is not
/// finalized against foreign content.
#[cfg(unix)]
pub(crate) async fn rename_beneath(
    root: &Path,
    from_dir_rel: &Path,
    from_leaf: &str,
    to_dir_rel: &Path,
    to_leaf: &str,
    expected_ino: (u64, u64),
) -> io::Result<()> {
    use rustix::fs::AtFlags;
    let root = root.to_path_buf();
    let from_dir_rel = from_dir_rel.to_path_buf();
    let from_leaf = from_leaf.to_string();
    let to_dir_rel = to_dir_rel.to_path_buf();
    let to_leaf = to_leaf.to_string();
    run_blocking(move || -> io::Result<()> {
        let from_fd = dir_beneath(&root, &from_dir_rel, false)?;
        let to_fd = dir_beneath(&root, &to_dir_rel, true)?;
        // Prove the source leaf is still the exact inode we hashed (no-follow):
        // reject a raced swap rather than promote foreign bytes under the digest.
        let st = rustix::fs::statat(&from_fd, from_leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if (st.st_dev as u64, st.st_ino as u64) != expected_ino {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        // No-replace rename onto the CAS leaf: a racer that installs a
        // symlink/file at `to_leaf` is not overwritten. `EEXIST` means the digest
        // already exists — idempotent success only if it is a regular file
        // (content-addressed, identical bytes), else rejected; our verified
        // staging inode is discarded on the dedup path.
        use rustix::fs::{FileType, RenameFlags};
        match rustix::fs::renameat_with(
            &from_fd,
            from_leaf.as_str(),
            &to_fd,
            to_leaf.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                rustix::fs::fsync(&to_fd).map_err(io::Error::from)?;
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
    })
    .await
}

/// Remove `leaf` from directory `dir_rel` (relative to `root`) via `unlinkat`
/// on a dirfd walked no-follow beneath `root`, so a symlinked parent cannot
/// redirect the deletion. Maps a missing entry / symlinked parent to `NotFound`.
#[cfg(unix)]
pub(crate) async fn unlink_beneath(root: &Path, dir_rel: &Path, leaf: &str) -> io::Result<()> {
    let root = root.to_path_buf();
    let dir_rel = dir_rel.to_path_buf();
    let leaf = leaf.to_string();
    run_blocking(move || -> io::Result<()> {
        let dirfd = dir_beneath(&root, &dir_rel, false)?;
        rustix::fs::unlinkat(&dirfd, leaf.as_str(), rustix::fs::AtFlags::empty())
            .map_err(io::Error::from)
    })
    .await
}

/// Create an empty file `leaf` inside `dir_rel` (relative to `root`), creating
/// the directory tree, via a dirfd walked no-follow beneath `root` and an
/// `O_CREAT|O_EXCL|O_NOFOLLOW` open. A symlink planted at any parent component
/// (or at `leaf` itself) cannot redirect the creation outside the store. Used to
/// stage an upload session (`<repo…>/uploads/<id>`) without following a planted
/// `uploads` symlink the way a path-based `File::create` would.
#[cfg(unix)]
pub(crate) async fn create_empty_beneath(
    root: &Path,
    dir_rel: &Path,
    leaf: &str,
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    let root = root.to_path_buf();
    let dir_rel = dir_rel.to_path_buf();
    let leaf = leaf.to_string();
    run_blocking(move || -> io::Result<()> {
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

/// Ensure `<repo…>` exists with a valid `oci-layout` marker, anchored to a dirfd
/// walked no-follow beneath `root` so a symlink planted at a repo path component
/// cannot redirect the marker write outside the store (the path-based
/// `create_dir_all`+`write` would follow it). Idempotent: an existing regular
/// marker is left as-is; the repo dir and its parent are fsynced so a blob-only
/// repository survives a crash. Returns whether the marker was newly written.
#[cfg(unix)]
pub(crate) async fn ensure_layout_beneath(
    root: &Path,
    repo_rel: &Path,
    marker: &str,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let root = root.to_path_buf();
    let repo_rel = repo_rel.to_path_buf();
    let marker = marker.to_string();
    run_blocking(move || -> io::Result<()> {
        use std::io::Write as _;
        let dirfd = dir_beneath(&root, &repo_rel, true)?;
        // Idempotent: a pre-existing regular `oci-layout` is the steady state.
        match rustix::fs::statat(&dirfd, "oci-layout", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "oci-layout exists and is not a regular file",
                ))
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        // Write the marker to a temp in the repo dirfd, fsync, then no-replace
        // rename into place (a racer creating it first is an idempotent win).
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
        match promote_temp_noreplace(&dirfd, tmp.as_str(), "oci-layout") {
            // A concurrent creator won the race: still success (idempotent).
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    })
    .await
}

/// Async wrapper: open `rel` beneath `root` read-only, no-follow at every
/// component (the symlink-escape backstop for blob reads).
#[cfg(unix)]
pub(crate) async fn open_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f = run_blocking(move || resolve_beneath(&root, &rel, OFlags::RDONLY)).await?;
    Ok(tokio::fs::File::from_std(f))
}

/// Async wrapper: open `rel` beneath `root` for appending, no-follow at every
/// component (so a planted `uploads` *or* `uploads/<id>` symlink cannot redirect
/// a PATCH append outside the store).
#[cfg(unix)]
pub(crate) async fn open_append_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f =
        run_blocking(move || resolve_beneath(&root, &rel, OFlags::WRONLY | OFlags::APPEND)).await?;
    Ok(tokio::fs::File::from_std(f))
}

/// The kind of a CAS entry resolved beneath `root` with no symlink traversal:
/// `Some(true)` = a regular file, `Some(false)` = present but not a regular
/// file (symlink/dir/etc.), `None` = absent. Never follows a symlink at any
/// path component.
#[cfg(unix)]
pub(crate) async fn stat_beneath(root: &Path, rel: &Path) -> io::Result<Option<(bool, u64)>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    run_blocking(move || -> io::Result<Option<(bool, u64)>> {
        // Walk to the parent no-follow, then no-follow-stat the final component.
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
                // A missing, symlinked, or non-directory parent means the entry
                // is not a valid CAS blob: report absent rather than error.
                // (`O_NOFOLLOW` on a symlink yields `ELOOP` on Linux, `ENOTDIR`
                // on macOS/BSD.) A genuine permission error (`EACCES`) is NOT
                // swallowed — it surfaces as a 500, not a false 404.
                Err(
                    rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR,
                ) => return Ok(None),
                Err(e) => return Err(io::Error::from(e)),
            }
        }
        // Stat the leaf no-follow. A missing/symlinked leaf is absent; a genuine
        // IO error propagates. In test, `FORCE_STAT_ERROR` injects a synthetic
        // errno so this error arm is covered deterministically (a real leaf stat
        // failure needs a fault a single-fs test cannot otherwise produce).
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
    })
    .await
}
