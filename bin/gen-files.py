"""Generate catalog detections; never execute driver samples."""
import argparse
import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path

LFS_POINTER_LIKE_PREFIX = b"version"
LFS_POINTER_MAX_BYTES = 1024
LFS_POINTER_PATTERN = re.compile(
    rb"\Aversion https://git-lfs.github.com/spec/v1\r?\n"
    rb"oid sha256:([0-9a-f]{64})\r?\n"
    rb"size (0|[1-9][0-9]*)\r?\n\Z"
)


class ClamAvHashListError(ValueError):
    """Raised when a driver cannot be represented safely in a ClamAV hash list."""


def _parse_lfs_pointer(data, file_path):
    """Return a Git LFS object's SHA256 and size, or None for binary content."""
    pointer_like = data.startswith(LFS_POINTER_LIKE_PREFIX) or (
        data and LFS_POINTER_LIKE_PREFIX.startswith(data)
    )
    if not pointer_like:
        return None

    if len(data) > LFS_POINTER_MAX_BYTES:
        raise ClamAvHashListError(
            f"Malformed or unsupported Git LFS pointer: {file_path}"
        )

    match = LFS_POINTER_PATTERN.fullmatch(data)
    if not match:
        raise ClamAvHashListError(
            f"Malformed or unsupported Git LFS pointer: {file_path}"
        )

    return match.group(1).decode("ascii"), int(match.group(2))


def _hash_binary_file(file_path):
    """Calculate a SHA256 and size without loading a driver into memory at once."""
    digest = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _clamav_hash_entry(file_path):
    """Create a ClamAV hash-list entry from a hydrated binary or Git LFS pointer."""
    with open(file_path, "rb") as stream:
        prefix = stream.read(LFS_POINTER_MAX_BYTES + 1)

    lfs_pointer = _parse_lfs_pointer(prefix, file_path)
    if lfs_pointer:
        return lfs_pointer
    return _hash_binary_file(file_path)


def gen_clamav_hash_list(
    drivers_path="drivers/", output_path="detections/av/LOLDrivers.hdb"
):
    """
    Generates ClamAV hash list in the format sha256_hash:filesize:signature_name.
    """
    drivers_path = os.fspath(drivers_path)
    output_path = os.fspath(output_path)
    if not os.path.isdir(drivers_path):
        raise ClamAvHashListError(f"Drivers directory does not exist: {drivers_path}")

    entries = []
    for root, directories, files in os.walk(drivers_path):
        directories.sort()
        for file_name in sorted(files):
            if not file_name.endswith(".bin"):
                continue
            full_path = os.path.join(root, file_name)
            sha256_hash, filesize = _clamav_hash_entry(full_path)
            relative_path = os.path.relpath(full_path, drivers_path)
            entries.append((relative_path, sha256_hash, filesize, file_name))

    if not entries:
        raise ClamAvHashListError(f"No .bin drivers found in: {drivers_path}")

    entries.sort(key=lambda entry: entry[0])
    output_dir = os.path.dirname(output_path) or "."
    os.makedirs(output_dir, exist_ok=True)
    try:
        output_mode = stat.S_IMODE(os.stat(output_path).st_mode) & 0o666
    except FileNotFoundError:
        output_mode = 0o644
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".LOLDrivers.hdb.", dir=output_dir, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as hdb:
            for _, sha256_hash, filesize, file_name in entries:
                hdb.write(f"{sha256_hash}:{filesize}:{file_name}\n")
        os.chmod(temporary_path, output_mode)
        os.replace(temporary_path, output_path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise

if __name__ == "__main__":
    from detection_generation import generate
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=root / "yaml")
    parser.add_argument("--output", type=Path, default=root)
    parser.add_argument("--drivers", type=Path, default=root / "drivers")
    args = parser.parse_args()
    outputs = generate(args.catalog, args.output, args.drivers)
    print(f"Generated {len(outputs)} owned artifacts")
