//! Crash-atomic CAS blob publication and cross-repo promotion, all anchored
//! to dirfds walked no-follow beneath the store root: reflink, then hard link,
//! then a streaming copy (SECURITY.md:124 contract order).

use crate::beneath::{dir_beneath, run_blocking};
use std::io;
use std::path::Path;

/// How a cross-repo promotion materialized the destination blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Promotion {
    /// A regular file was already at the destination (idempotent).
    Existing,
    /// `FICLONE` copy-on-write clone (the contract primary).
    Reflink,
    /// `linkat` hard link (the logged fallback).
    Hardlink,
    /// Streaming copy (cross-device / no-hardlink).
    Copy,
}

impl Promotion {
    /// Low-cardinality metric label for this mechanism.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Promotion::Existing => "existing",
            Promotion::Reflink => "reflink",
            Promotion::Hardlink => "hardlink",
            Promotion::Copy => "copy",
        }
    }
}

/// Promote a blob named `leaf` from `from_alg_rel` into `to_alg_rel` (both
/// directories relative to `root`), for a cross-repo mount or dedupe.
/// Everything is anchored to dirfds walked no-follow beneath `root`, so a
/// symlinked `repo`, `blobs`, or `<alg>` parent on either side cannot redirect
/// the promotion. Contract order (SECURITY.md:124): **reflink first**
/// (`FICLONE` into a temp opened in the destination dirfd, then `renameat` —
/// CoW, independent deletion), then a **hard link** (`linkat` between dirfds,
/// O(1) same-fs), then — only when `allow_copy` — a **streaming copy**
/// (cross-device / no-hardlink); without it the hard-link error is returned so
/// a dedupe caller keeps its own copy instead. A pre-existing destination is
/// re-validated no-follow as a regular file (idempotent success) or rejected.
#[cfg(unix)]
pub(crate) async fn mount_promote_beneath(
    root: &Path,
    from_alg_rel: &Path,
    to_alg_rel: &Path,
    leaf: &str,
    allow_copy: bool,
    sync: bool,
) -> io::Result<Promotion> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let root = root.to_path_buf();
    let from_alg_rel = from_alg_rel.to_path_buf();
    let to_alg_rel = to_alg_rel.to_path_buf();
    let leaf = leaf.to_string();
    run_blocking(move || -> io::Result<Promotion> {
        let from_dir = dir_beneath(&root, &from_alg_rel, false)?;
        let to_dir = dir_beneath(&root, &to_alg_rel, true)?;
        // Open the source no-follow (the caller already verified via blob_exists
        // that it is a present regular file beneath the root).
        let src = rustix::fs::openat(
            &from_dir,
            leaf.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let mut src_file = std::fs::File::from(src);
        // Prove the opened source is a *regular file* on the fd we hold — not the
        // path. `O_NOFOLLOW` refuses a symlink leaf, but a FIFO/socket/device
        // planted at the source name is still openable (`O_NONBLOCK` keeps the
        // open from blocking) and would otherwise be reflink/copy-read or, worse,
        // hard-linked into the CAS as a non-regular inode. Bind the check to the
        // inode we will actually promote by fstat'ing the descriptor.
        {
            let st = rustix::fs::fstat(&src_file).map_err(io::Error::from)?;
            if !FileType::from_raw_mode(st.st_mode).is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mount source is not a regular file",
                ));
            }
        }
        // Treat a pre-existing regular-file destination as idempotent success; a
        // symlink/dir/other there is rejected (re-checked here, not only in the
        // caller's earlier stat, to close the check→promote race). A missing dest
        // (NOENT) proceeds to promotion; any other stat error propagates.
        match rustix::fs::statat(&to_dir, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => {
                return Ok(Promotion::Existing)
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "mount destination exists and is not a regular file",
                ))
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        // Write into a unique temp in the destination dir (no-follow), by
        // reflink where possible else a streaming copy, then renameat into place.
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(io::Error::other)?;
        let tmp = format!(".{}.{}.tmp", leaf, hex::encode(rnd));
        let promote_via_temp = |flags: OFlags| -> io::Result<std::fs::File> {
            rustix::fs::openat(
                &to_dir,
                tmp.as_str(),
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | flags,
                Mode::from_raw_mode(0o644),
            )
            .map(std::fs::File::from)
            .map_err(io::Error::from)
        };
        // First try a hard link (O(1), no temp) — skipped when a reflink is
        // preferred and available. Reflink is the contract primary, so attempt it
        // into the temp; if the filesystem cannot reflink, hard-link directly;
        // if that also fails (cross-device), stream-copy into the temp.
        let mut out = promote_via_temp(OFlags::empty())?;
        if try_reflink(&mut out, &mut src_file) {
            if sync {
                out.sync_data()?;
            }
            drop(out);
            promote_temp_noreplace(&to_dir, tmp.as_str(), leaf.as_str(), sync)?;
            return Ok(Promotion::Reflink);
        }
        // Reflink unavailable: drop the temp and try a direct hard link.
        drop(out);
        let _ = rustix::fs::unlinkat(&to_dir, tmp.as_str(), AtFlags::empty());
        match try_hardlink_at(&from_dir, leaf.as_str(), &to_dir, leaf.as_str()) {
            Ok(()) => {
                if sync {
                    rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
                }
                Ok(Promotion::Hardlink)
            }
            // Destination raced in between our earlier stat and this link. Accept
            // it as idempotent success ONLY if it is now a regular file, re-checked
            // no-follow — `EEXIST` alone also fires for a symlink/dir/other planted
            // in the race, which must not count as a valid CAS blob (would 201 a
            // bogus entry). Mirrors the pre-link destination check above.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match rustix::fs::statat(&to_dir, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => {
                        if sync {
                            rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
                        }
                        Ok(Promotion::Existing)
                    }
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "mount destination exists and is not a regular file",
                    )),
                    Err(e) => Err(io::Error::from(e)),
                }
            }
            // Cross-device / no-hardlink: stream-copy into a fresh temp + rename.
            Err(_) if allow_copy => {
                let mut out = promote_via_temp(OFlags::empty())?;
                stream_copy(&mut src_file, &mut out)?;
                if sync {
                    out.sync_data()?;
                }
                drop(out);
                promote_temp_noreplace(&to_dir, tmp.as_str(), leaf.as_str(), sync)?;
                Ok(Promotion::Copy)
            }
            Err(e) => Err(e),
        }
    })
    .await
}

/// Atomically move the temp `tmp` onto `leaf` in `to_dir` with **no-replace**
/// semantics (`renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)`
/// on Apple), then (when `sync`) fsync the dir. Plain `renameat` has replace semantics: a
/// racer that installs a symlink or a different file at `leaf` between the
/// caller's no-follow check and the rename would be silently overwritten (or the
/// symlink followed on a later replace). NOREPLACE closes that window — the
/// rename fails `EEXIST` if anything is at `leaf`, which is accepted as an
/// idempotent dedup hit ONLY when the existing entry is a regular file
/// (re-validated no-follow); a symlink/dir/other is rejected. The leftover temp
/// is removed on the idempotent path so no orphan survives.
#[cfg(unix)]
pub(crate) fn promote_temp_noreplace(
    to_dir: &std::os::fd::OwnedFd,
    tmp: &str,
    leaf: &str,
    sync: bool,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, RenameFlags};
    match rustix::fs::renameat_with(to_dir, tmp, to_dir, leaf, RenameFlags::NOREPLACE) {
        Ok(()) => {
            if sync {
                rustix::fs::fsync(to_dir).map_err(io::Error::from)?;
            }
            Ok(())
        }
        // Something is already at `leaf`. Accept only a regular file (idempotent
        // dedup — content-addressed, so identical bytes); reject a raced
        // symlink/dir/other. Drop our now-unneeded temp either way.
        Err(rustix::io::Errno::EXIST) => {
            let st = rustix::fs::statat(to_dir, leaf, AtFlags::SYMLINK_NOFOLLOW);
            let _ = rustix::fs::unlinkat(to_dir, tmp, AtFlags::empty());
            match st {
                Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => Ok(()),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CAS destination exists and is not a regular file",
                )),
                Err(e) => Err(io::Error::from(e)),
            }
        }
        Err(e) => {
            let _ = rustix::fs::unlinkat(to_dir, tmp, AtFlags::empty());
            Err(io::Error::from(e))
        }
    }
}

/// `linkat` between two dirfds, with a test-only fault seam: when
/// `FORCE_COPY_FALLBACK` is set it returns an `EXDEV`-shaped error so the copy
/// fallback runs deterministically on a single filesystem.
#[cfg(unix)]
pub(crate) fn try_hardlink_at(
    from_dir: &std::os::fd::OwnedFd,
    from_leaf: &str,
    to_dir: &std::os::fd::OwnedFd,
    to_leaf: &str,
) -> io::Result<()> {
    if fault!(FORCE_COPY_FALLBACK) {
        return Err(io::Error::from_raw_os_error(18)); // EXDEV
    }
    rustix::fs::linkat(
        from_dir,
        from_leaf,
        to_dir,
        to_leaf,
        rustix::fs::AtFlags::empty(),
    )
    .map_err(io::Error::from)
}

#[cfg(target_os = "linux")]
pub(crate) fn try_reflink(output: &mut std::fs::File, input: &mut std::fs::File) -> bool {
    if fault!(FORCE_COPY_FALLBACK) {
        return false;
    }
    if fault!(FORCE_REFLINK_OK) {
        // Simulate a successful whole-file reflink by actually moving the bytes
        // (ext4 in CI has no CoW), so the "reflink succeeded" branch is covered
        // with a correct destination.
        return stream_copy(input, output).is_ok();
    }
    rustix::fs::ioctl_ficlone(&*output, &*input).is_ok()
}

/// Non-Linux: no `FICLONE`, so a reflink is never available (the caller falls
/// back to a hard link, then a streaming copy).
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn try_reflink(_output: &mut std::fs::File, _input: &mut std::fs::File) -> bool {
    false
}

/// Rewind both files and copy `input` to `output` with a buffered read/write
/// loop, first truncating the destination so a retry never leaves stale tail
/// bytes. The streaming fallback used when a reflink is not possible. Runs on
/// the blocking thread that owns the file handles.
#[cfg(unix)]
pub(crate) fn stream_copy(input: &mut std::fs::File, output: &mut std::fs::File) -> io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    input.seek(SeekFrom::Start(0))?;
    output.seek(SeekFrom::Start(0))?;
    output.set_len(0)?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

/// Publish `data` as the CAS blob named `leaf` inside the directory `alg_rel`
/// (relative to `root`, e.g. `<repo…>/blobs/<alg>`) with a per-operation unique
/// temp sibling, fsync (when `sync`), and atomic rename — all **relative to a dirfd walked
/// no-follow beneath `root`**, so a symlinked `repo`/`blobs`/`<alg>` parent
/// cannot redirect the write outside the store. Portable across every platform
/// and the fallback the Linux `O_TMPFILE` path degrades to. A rename onto an
/// existing blob is harmless (content-addressed: identical bytes).
#[cfg(unix)]
pub(crate) async fn publish_bytes_rename(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
    sync: bool,
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write as _;
    let root = root.to_path_buf();
    let alg_rel = alg_rel.to_path_buf();
    let leaf = leaf.to_string();
    let data = data.to_vec();
    run_blocking(move || -> io::Result<()> {
        let dirfd = dir_beneath(&root, &alg_rel, true)?;
        let mut tmp = [0u8; 8];
        getrandom::fill(&mut tmp).map_err(io::Error::other)?;
        let tmp_name = format!(".{}.{}.tmp", leaf, hex::encode(tmp));
        let fd = rustix::fs::openat(
            &dirfd,
            tmp_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(io::Error::from)?;
        let mut f = std::fs::File::from(fd);
        f.write_all(&data)?;
        if sync {
            f.sync_data()?;
        }
        drop(f);
        // No-replace promotion: a raced symlink/file at `leaf` is not silently
        // overwritten; an `EEXIST` is a dedup hit only if the existing entry is a
        // regular file (matches the Linux O_TMPFILE+linkat path's contract).
        promote_temp_noreplace(&dirfd, tmp_name.as_str(), leaf.as_str(), sync)
    })
    .await
}

/// Publish `data` as the CAS blob `leaf` inside `alg_rel` crash-atomically,
/// anchored to a dirfd walked no-follow beneath `root`. On Linux this opens an
/// anonymous `O_TMPFILE` inode in the (beneath-root) directory, writes (and,
/// when `sync`, fsyncs) it, then `linkat`s it into place: a partial blob is never visible under its
/// digest name and no orphan temp survives a crash. A filesystem without
/// `O_TMPFILE` degrades to the portable temp+rename path. `linkat` `EEXIST`
/// means a blob already exists at the name; it is dedup success only if that
/// entry is a *regular file* (validated no-follow via the dirfd) — a planted
/// symlink/dir is rejected. Non-Linux platforms use the temp+rename path.
#[cfg(target_os = "linux")]
pub(crate) async fn publish_bytes(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
    sync: bool,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::io::Write as _;
    use std::os::fd::AsRawFd;
    let root_buf = root.to_path_buf();
    let alg_rel_buf = alg_rel.to_path_buf();
    let leaf_buf = leaf.to_string();
    let data_vec = data.to_vec();
    let outcome = run_blocking(move || -> io::Result<bool> {
        let dirfd = dir_beneath(&root_buf, &alg_rel_buf, true)?;
        // Anonymous inode in the (beneath-root) target directory. In test,
        // `FORCE_TMPFILE_UNSUPPORTED` simulates a filesystem without O_TMPFILE so
        // the fallback arm runs deterministically (ext4 in CI always supports it).
        let opened = if fault!(FORCE_TMPFILE_UNSUPPORTED) {
            Err(Errno::OPNOTSUPP)
        } else {
            rustix::fs::openat(
                &dirfd,
                ".",
                OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
        };
        let fd = match opened {
            Ok(fd) => fd,
            // O_TMPFILE unavailable → signal the portable temp+rename fallback.
            Err(_) => return Ok(false),
        };
        let mut f = std::fs::File::from(fd);
        f.write_all(&data_vec)?;
        if sync {
            f.sync_data()?;
        }
        // Link the anonymous inode into place via its /proc/self/fd magic link,
        // relative to the beneath-root dirfd (AT_EMPTY_PATH would need
        // CAP_DAC_READ_SEARCH).
        let proc_path = format!("/proc/self/fd/{}", f.as_raw_fd());
        match rustix::fs::linkat(
            rustix::fs::CWD,
            proc_path,
            &dirfd,
            leaf_buf.as_str(),
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => {}
            // A blob already exists at the name: dedup success only if it is a
            // regular file (no-follow, via the dirfd). A planted symlink/dir is
            // rejected — never reported present nor later followed on read.
            Err(Errno::EXIST) => {
                let st = rustix::fs::statat(&dirfd, leaf_buf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io::Error::from)?;
                if !FileType::from_raw_mode(st.st_mode).is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "CAS destination exists and is not a regular file",
                    ));
                }
            }
            Err(e) => return Err(io::Error::from(e)),
        }
        if sync {
            rustix::fs::fsync(&dirfd).map_err(io::Error::from)?;
        }
        Ok(true)
    })
    .await?;
    if !outcome {
        return publish_bytes_rename(root, alg_rel, leaf, data, sync).await;
    }
    Ok(())
}

/// Non-Linux **Unix** publish (macOS/BSD): portable dirfd-anchored temp+rename.
/// Gated `all(unix, not(linux))` to match `publish_bytes_rename`/`try_reflink`
/// and the rest of the dirfd machinery — the whole `FsStorage` storage path is
/// Unix-only (no Windows target; see the Unix-gated `resolve_beneath`/dirfd
/// helpers), so this must not claim to cover a non-Unix `not(linux)` platform
/// where its `#[cfg(unix)]` callee `publish_bytes_rename` does not exist.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) async fn publish_bytes(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
    sync: bool,
) -> io::Result<()> {
    publish_bytes_rename(root, alg_rel, leaf, data, sync).await
}
