"""Deterministic OCI image-layout fixture for the crane phase."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import random
import tarfile

SIZES = [64 << 20, 16 << 20, 4 << 20, 1 << 20, 256 << 10, 16 << 10]


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _write_blob(root: str, data: bytes) -> str:
    h = hashlib.sha256(data).hexdigest()
    with open(os.path.join(root, "blobs", "sha256", h), "wb") as f:
        f.write(data)
    return "sha256:" + h


def build_app_layout(dir: str, seed: int) -> str:
    """Write a valid OCI layout to `dir`; return the manifest digest."""
    os.makedirs(os.path.join(dir, "blobs", "sha256"), exist_ok=True)
    layers, diff_ids = [], []
    for k, size in enumerate(SIZES):
        payload = random.Random(f"{seed}/app/{k}").randbytes(size)
        tbuf = io.BytesIO()
        with tarfile.open(fileobj=tbuf, mode="w", format=tarfile.PAX_FORMAT) as tf:
            ti = tarfile.TarInfo("data.bin")
            ti.size, ti.mtime, ti.uid, ti.gid, ti.mode = size, 0, 0, 0, 0o644
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(payload))
        tar = tbuf.getvalue()
        diff_ids.append("sha256:" + hashlib.sha256(tar).hexdigest())
        zbuf = io.BytesIO()
        with gzip.GzipFile(fileobj=zbuf, mode="wb", mtime=0, compresslevel=1) as gz:
            gz.write(tar)
        gzb = zbuf.getvalue()
        layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                       "digest": _write_blob(dir, gzb), "size": len(gzb)})
    cfg = _canon({"architecture": "amd64", "os": "linux",
                  "rootfs": {"type": "layers", "diff_ids": diff_ids}, "config": {}})
    man = _canon({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                  "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                             "digest": _write_blob(dir, cfg), "size": len(cfg)},
                  "layers": layers})
    md = _write_blob(dir, man)
    with open(os.path.join(dir, "oci-layout"), "w") as f:
        f.write('{"imageLayoutVersion":"1.0.0"}')
    with open(os.path.join(dir, "index.json"), "wb") as f:
        f.write(_canon({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                       "digest": md, "size": len(man)}]}))
    return md


def layout_bytes(dir: str) -> int:
    """Total blob bytes transferred by one push/pull of the layout."""
    d = os.path.join(dir, "blobs", "sha256")
    return sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
