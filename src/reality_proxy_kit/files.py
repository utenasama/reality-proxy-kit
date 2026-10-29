"""Small file primitives; secrets are never an implicit stdout result."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def revision(data):
    return digest(canonical(data))


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Private directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def atomic_write(path, data, mode=0o600, *, exclusive=False):
    path = Path(path)
    if path.is_symlink() or (exclusive and path.exists()):
        raise ValueError("Refusing to replace an existing private output")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if isinstance(data, str):
        data = data.encode()
    fd, tmp = tempfile.mkstemp(prefix=".rpk-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        if exclusive:
            os.link(tmp, path)
            os.unlink(tmp)
        else:
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path, data, **kwargs):
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", **kwargs)


def require_private_output(path, root):
    """Do not generate credentials in tracked source trees."""
    path, root = Path(path).resolve(), Path(root).resolve()
    if path.is_relative_to(root) and not path.is_relative_to(root / "private"):
        raise ValueError("Secret outputs within the checkout must be under private/")
    return path
