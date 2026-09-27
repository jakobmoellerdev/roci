//! Crash-atomic CAS blob publication and cross-repo promotion beneath the
//! store root (SECURITY.md:124 contract order: reflink → hard link → copy).

use crate::beneath::{dir_beneath, run_blocking};
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Promotion {
    Existing,
    Reflink,
    Hardlink,
    /// Streaming copy (cross-device fallback).
    Copy,
}

impl Promotion {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Promotion::Existing => "existing",
            Promotion::Reflink => "reflink",
            Promotion::Hardlink => "hardlink",
            Promotion::Copy => "copy",
        }
    }
}

/// Promote a blob from `from_alg_rel` into `to_alg_rel` via dirfds beneath
/// `root`. Contract order (SECURITY.md:124): reflink → hard link → streaming copy.
#[cfg(unix)]
pub(crate) async fn mount_promote_beneath(
    root: &Path,
    from_alg_rel: &Path,
    to_alg_rel: &Path,
    leaf: &str,
    allow_copy: bool,
    sync: bool,
) -> io::Result<Promotion> {
    let root = root.to_path_buf();
    let from_alg_rel = from_alg_rel.to_path_buf();
    let to_alg_rel = to_alg_rel.to_path_buf();
    let leaf = leaf.to_string();
    let span = tracing::info_span!("cas.link", mechanism = tracing::field::Empty);
    let result = run_blocking("mount_promote_beneath", {
        let span = span.clone();
        move || {
            let _guard = span.enter();
            mount_promote_beneath_sync(root, from_alg_rel, to_alg_rel, leaf, allow_copy, sync)
        }
    })
    .await;
    // Record mechanism on the span after blocking work completes.
    if let Ok(promo) = &result {
        span.record("mechanism", promo.label());
    }
    result
}

/// Synchronous body of [`mount_promote_beneath`].
#[cfg(unix)]
pub(crate) fn mount_promote_beneath_sync(
    root: std::path::PathBuf,
    from_alg_rel: std::path::PathBuf,
    to_alg_rel: std::path::PathBuf,
    leaf: String,
    allow_copy: bool,
    sync: bool,
) -> io::Result<Promotion> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let from_dir = dir_beneath(&root, &from_alg_rel, false)?;
    let to_dir = dir_beneath(&root, &to_alg_rel, true)?;
    // Open source no-follow.
    let src = rustix::fs::openat(
        &from_dir,
        leaf.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut src_file = std::fs::File::from(src);
    // SECURITY: fstat the fd (not path) to reject a planted FIFO/device/socket
    // that O_NOFOLLOW+O_NONBLOCK would still open.
    {
        let st = rustix::fs::fstat(&src_file).map_err(io::Error::from)?;
        if !FileType::from_raw_mode(st.st_mode).is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mount source is not a regular file",
            ));
        }
    }
    // Pre-existing regular file = idempotent; symlink/dir rejected; missing proceeds.
    match rustix::fs::statat(&to_dir, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => return Ok(Promotion::Existing),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "mount destination exists and is not a regular file",
            ))
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(io::Error::from(e)),
    }
    // Temp in destination dir, try reflink then hardlink then copy.
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
    // Try reflink (contract primary) into temp, else hardlink, else copy.
    let mut out = promote_via_temp(OFlags::empty())?;
    if try_reflink(&mut out, &mut src_file) {
        if sync {
            out.sync_data()?;
        }
        drop(out);
        promote_temp_noreplace(&to_dir, tmp.as_str(), leaf.as_str(), sync)?;
        return Ok(Promotion::Reflink);
    }
    // Reflink unavailable: try a direct hard link.
    drop(out);
    let _ = rustix::fs::unlinkat(&to_dir, tmp.as_str(), AtFlags::empty());
    match try_hardlink_at(&from_dir, leaf.as_str(), &to_dir, leaf.as_str()) {
        Ok(()) => {
            if sync {
                rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
            }
            Ok(Promotion::Hardlink)
        }
        // EEXIST: accept only if a regular file (SECURITY: no symlink/dir).
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
        // Cross-device: stream-copy into a fresh temp + rename.
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
}

/// `renameat2(RENAME_NOREPLACE)` rename: `EEXIST` accepted only when the existing
/// entry is a regular file (no-follow). Cleans up the temp on all paths.
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
        // EEXIST: accept only a regular file (dedup); reject symlink/dir.
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

/// `linkat` between dirfds; `FORCE_COPY_FALLBACK` injects EXDEV in tests.
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
        // Simulate reflink via copy so the reflink branch is covered in CI.
        return stream_copy(input, output).is_ok();
    }
    rustix::fs::ioctl_ficlone(&*output, &*input).is_ok()
}

/// Non-Linux: no `FICLONE`; always returns `false`.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn try_reflink(_output: &mut std::fs::File, _input: &mut std::fs::File) -> bool {
    false
}

/// Streaming copy fallback: rewind, truncate destination, buffered copy.
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

/// Publish `data` as CAS blob `leaf` in `alg_rel` via temp+rename beneath `root`.
#[cfg(unix)]
pub(crate) fn publish_bytes_rename_sync(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
    sync: bool,
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write as _;
    let dirfd = dir_beneath(root, alg_rel, true)?;
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
    f.write_all(data)?;
    if sync {
        f.sync_data()?;
    }
    drop(f);
    // No-replace promotion; EEXIST is dedup only if regular file.
    promote_temp_noreplace(&dirfd, tmp_name.as_str(), leaf, sync)
}

/// Linux: publish via `O_TMPFILE` + `linkat` (crash-atomic, no orphan temps).
/// Falls back to [`publish_bytes_rename_sync`] without `O_TMPFILE`.
#[cfg(target_os = "linux")]
pub(crate) fn publish_bytes_sync(
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
    let dirfd = dir_beneath(root, alg_rel, true)?;
    // O_TMPFILE anonymous inode; FORCE_TMPFILE_UNSUPPORTED triggers fallback.
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
    let Ok(fd) = opened else {
        // O_TMPFILE unavailable → portable temp+rename fallback.
        return publish_bytes_rename_sync(root, alg_rel, leaf, data, sync);
    };
    let mut f = std::fs::File::from(fd);
    f.write_all(data)?;
    if sync {
        f.sync_data()?;
    }
    // Link via /proc/self/fd (AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH).
    let proc_path = format!("/proc/self/fd/{}", f.as_raw_fd());
    match rustix::fs::linkat(
        rustix::fs::CWD,
        proc_path,
        &dirfd,
        leaf,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => {}
        // EEXIST: dedup only if regular file (no-follow); planted symlink rejected.
        Err(Errno::EXIST) => {
            let st = rustix::fs::statat(&dirfd, leaf, AtFlags::SYMLINK_NOFOLLOW)
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
    Ok(())
}

/// [`publish_bytes_sync`] / [`publish_bytes_rename_sync`] as one blocking-pool hop.
#[cfg(unix)]
pub(crate) async fn publish_bytes(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
    sync: bool,
) -> io::Result<()> {
    let (root, alg_rel, leaf, data) = (
        root.to_path_buf(),
        alg_rel.to_path_buf(),
        leaf.to_string(),
        data.to_vec(),
    );
    run_blocking("publish_bytes", move || {
        #[cfg(target_os = "linux")]
        {
            publish_bytes_sync(&root, &alg_rel, &leaf, &data, sync)
        }
        #[cfg(not(target_os = "linux"))]
        {
            publish_bytes_rename_sync(&root, &alg_rel, &leaf, &data, sync)
        }
    })
    .await
}
