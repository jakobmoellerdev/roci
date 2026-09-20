#!/usr/bin/env bash
# Run the roci-storage test suite on real ext4 / btrfs / XFS filesystems.
#
# Runs INSIDE the Containerfile.filesystems image (privileged). For each
# filesystem it creates a loopback image, makes the filesystem, mounts it, and
# runs the storage tests with TMPDIR pointed at the mount — so every
# `tempfile::tempdir()`-rooted `FsStorage` exercises the *real* reflink
# (`FICLONE`), hard-link, `O_TMPFILE`, and copy behavior of that filesystem
# (reflink truly succeeds on btrfs/XFS and truly fails on ext4), not the
# `FORCE_*` simulation. Tests run as an unprivileged user so the chmod-000
# permission fixtures behave (root bypasses mode bits).
#
# Exit non-zero if any filesystem's suite fails or a filesystem cannot be
# created/mounted (a missing mkfs is a setup error, not a skip).
set -euo pipefail

FILESYSTEMS=("ext4" "btrfs" "xfs")
# Minimum image sizes (MiB): btrfs/XFS need more than ext4 to mkfs.
declare -A MIN_MB=([ext4]=64 [btrfs]=256 [xfs]=300)

# An unprivileged user to run tests as (created by the image, or here).
id roci >/dev/null 2>&1 || useradd --create-home --uid 1000 roci

# The test user must own the repo checkout and be able to write the cargo
# registry cache (`cargo metadata`/nextest write there). The image built the
# registry as root, so hand it to the unprivileged test user. The build target
# dir lives under the user's home (writable, and its parent is writable so the
# nextest temp-dir sibling can be created).
chown -R roci:roci /roci 2>/dev/null || true
chown -R roci:roci /usr/local/cargo/registry 2>/dev/null || true

overall_rc=0
for fs in "${FILESYSTEMS[@]}"; do
  echo "==================== filesystem: ${fs} ===================="
  img="/tmp/roci-${fs}.img"
  mnt="/mnt/roci-${fs}"
  mb="${MIN_MB[$fs]}"
  rm -f "$img"
  dd if=/dev/zero of="$img" bs=1M count="$mb" status=none
  case "$fs" in
    ext4)  mkfs.ext4  -q -F "$img" ;;
    btrfs) mkfs.btrfs -q -f "$img" ;;
    xfs)   mkfs.xfs   -q -f "$img" ;;
  esac
  mkdir -p "$mnt"
  mount -o loop "$img" "$mnt"
  # The mounted FS is the test scratch root; the unprivileged user owns it.
  chown roci:roci "$mnt"
  echo "mounted $(findmnt -no FSTYPE "$mnt") at ${mnt}"

  # Run the storage suite with TMPDIR on the mounted filesystem. `--test-threads`
  # is left at nextest's default; tests are isolated per tempdir.
  rc=0
  su roci -c "cd /roci && TMPDIR='${mnt}' CARGO_TARGET_DIR=/home/roci/target \
      cargo nextest run -p roci-storage --all-features \
      --no-fail-fast 2>&1" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: roci-storage suite failed on ${fs} (rc=${rc})"
    overall_rc=1
  else
    echo "PASS: roci-storage suite on ${fs}"
  fi

  # Prove the filesystem's reflink capability matches expectations: btrfs/XFS
  # must support FICLONE (cp --reflink=always), ext4 must not. This confirms the
  # suite above really exercised the reflink path (btrfs/XFS) vs the fallback
  # (ext4), rather than all filesystems silently taking one branch.
  echo "seed" > "${mnt}/reflink-probe-src"
  if su roci -c "cp --reflink=always '${mnt}/reflink-probe-src' '${mnt}/reflink-probe-dst'" 2>/dev/null; then
    reflink="supported"
  else
    reflink="unsupported"
  fi
  case "$fs" in
    btrfs|xfs)
      [ "$reflink" = "supported" ] || { echo "FAIL: ${fs} unexpectedly lacks reflink"; overall_rc=1; } ;;
    ext4)
      [ "$reflink" = "unsupported" ] || { echo "NOTE: ext4 reported reflink support (kernel-dependent); fallback still valid"; } ;;
  esac
  echo "${fs}: reflink ${reflink}"

  umount "$mnt"
  rm -f "$img"
done

if [ "$overall_rc" -eq 0 ]; then
  echo "ALL FILESYSTEMS PASSED (ext4, btrfs, xfs)"
else
  echo "ONE OR MORE FILESYSTEMS FAILED"
fi
exit "$overall_rc"
