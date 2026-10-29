"""Authenticated controller-side recovery snapshots; keys are separate files."""
import base64
import json
from pathlib import Path, PurePosixPath
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .files import atomic_write, canonical, digest, private_directory, read_json, write_json
from .model import Deployment
from .state import validate

MAGIC = b"RPKBACKUP\x01"
LIMIT = 256 * 1024 * 1024


def create(spec, state, output, key_file, extra=None):
    deployment = Deployment(spec)
    validate(state, deployment)
    output, key_file = Path(output).resolve(), Path(key_file).resolve()
    if output == key_file or output.parent == key_file.parent:
        raise ValueError("Keep the backup and decryption key in separate directories")
    extra = extra or {}
    if state["management"] == "panel" and "panel.db" not in extra:
        raise ValueError("Panel backup requires a consistent live database snapshot")
    if output.exists():
        raise ValueError("Backup output already exists")
    if key_file.exists():
        if key_file.stat().st_mode & 0o077:
            raise ValueError("Decryption key must have private permissions")
        key = key_file.read_bytes()
    else:
        private_directory(key_file.parent)
        key = AESGCM.generate_key(bit_length=256)
        atomic_write(key_file, key, exclusive=True)
    if len(key) != 32:
        raise ValueError("Invalid backup key length")
    payload = {"schema": 1, "management": state["management"], "spec": spec, "state": state,
               "files": {n: {"data": base64.b64encode(v).decode(), "sha256": digest(v)} for n, v in extra.items()}}
    for name in payload["files"]:
        safe_name(name)
    data = canonical(payload)
    if len(data) > LIMIT:
        raise ValueError("Snapshot exceeds the supported size")
    nonce = secrets.token_bytes(12)
    private_directory(output.parent)
    atomic_write(output, MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC), exclusive=True)
    return {"format": 1, "management": state["management"], "sha256": digest(output.read_bytes())}


def safe_name(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or str(p) != name or "\\" in name or not p.parts:
        raise ValueError("Invalid snapshot member path")


def read(archive, key_file):
    if Path(archive).stat().st_size > LIMIT + 128:
        raise ValueError("Snapshot exceeds the supported size")
    data = Path(archive).read_bytes()
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 28:
        raise ValueError("Unknown or truncated backup format")
    key = Path(key_file).read_bytes()
    try:
        raw = AESGCM(key).decrypt(data[len(MAGIC):len(MAGIC) + 12], data[len(MAGIC) + 12:], MAGIC)
    except Exception:
        raise ValueError("Backup authentication failed; wrong key or damaged archive") from None
    payload = json.loads(raw)
    if payload.get("schema") != 1 or payload.get("management") != payload["state"]["management"]:
        raise ValueError("Unsupported backup schema or management mode")
    validate(payload["state"], Deployment(payload["spec"]))
    if payload["management"] == "panel" and "panel.db" not in payload["files"]:
        raise ValueError("Panel database is missing")
    for name, record in payload["files"].items():
        safe_name(name)
        if digest(base64.b64decode(record["data"], validate=True)) != record["sha256"]:
            raise ValueError("Backup member integrity failed")
    return payload


def restore(archive, key_file, directory):
    payload = read(archive, key_file)
    directory = Path(directory)
    if directory.exists():
        raise ValueError("Restore only to a new private directory; never overwrite live state")
    private_directory(directory)
    write_json(directory / "deployment.json", payload["spec"], exclusive=True)
    write_json(directory / "state.json", payload["state"], exclusive=True)
    for name, record in payload["files"].items():
        atomic_write(directory / name, base64.b64decode(record["data"]), exclusive=True)
    return {"management": payload["management"], "files": len(payload["files"]), "directory": str(directory.resolve())}
