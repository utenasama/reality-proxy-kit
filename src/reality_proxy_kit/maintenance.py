"""Private stdin/stdout protocol used only through verified SSH."""
import base64
import fcntl
import json
from pathlib import Path
import subprocess
import sys
from . import panel
from .config import panel_template
from .files import read_json, revision, write_json
from .model import Deployment
from .remote import BASE, RECEIPT, drift, run, verify


def snapshot():
    spec, seed = Deployment(read_json(BASE / "deployment.json")), read_json(BASE / "state.json")
    receipt = read_json(RECEIPT)
    if drift(receipt):
        raise ValueError("Managed files drifted")
    files = {}
    if seed["management"] == "panel":
        state, db, token = panel.snapshot(spec, seed)
        files["panel.db"] = base64.b64encode(db).decode()
    else:
        state, token = seed, revision(seed)
    for name in ("fullchain.pem", "privkey.pem"):
        path = BASE / "tls" / name
        if path.exists():
            files["tls/" + name] = base64.b64encode(path.read_bytes()).decode()
    static = Path("/var/www/reality-proxy-kit")
    if static.exists():
        for path in static.rglob("*"):
            if path.is_symlink():
                raise ValueError("Unexpected static symlink")
            if path.is_file():
                files["site/" + str(path.relative_to(static))] = base64.b64encode(path.read_bytes()).decode()
    return {"deployment": spec.data, "state": state, "token": token, "files": files, "revision": receipt["revision"]}


def main():
    with open(BASE / "operation.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = json.load(sys.stdin)
        if request["action"] == "snapshot":
            result = snapshot()
        elif request["action"] == "account":
            spec, seed = Deployment(read_json(BASE / "deployment.json")), read_json(BASE / "state.json")
            if seed["management"] != "panel":
                raise ValueError("Core accounts are managed on the controller")
            if drift(read_json(RECEIPT)):
                raise ValueError("Managed files drifted")
            new = panel.change_account(spec, seed, request["operation"], request["name"], request.get("routes"), request["expected"])
            # Account authority remains native. This updates only the recovery seed
            # and tombstones; snapshot always reads actual native accounts/grants.
            write_json(BASE / "state.json", new)
            run(["systemctl", "restart", "x-ui"])
            result = {"changed": True, "existing_sessions": "entry restart interrupts active sessions"}
        else:
            raise ValueError("Unsupported maintenance operation")
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": "Maintenance failed; native state may have partially changed. Refresh and diagnose before retry."}), file=sys.stderr)
        raise SystemExit(1)
