"""Root-only host transaction runner. Also executable before package installation.

No production defaults, curl-to-shell, unpinned core replacement, or global nft flush.
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

BASE = Path("/etc/reality-proxy-kit")
RECEIPT = BASE / "receipt.json"
LIMIT = 512 * 1024 * 1024


def run(argv, *, check=True):
    result = subprocess.run(argv, capture_output=True, timeout=900)
    if check and result.returncode:
        if BASE.exists():
            write(BASE / "last-command-error.json", json.dumps({"program": Path(argv[0]).name, "exit": result.returncode,
                                                               "stderr": result.stderr.decode(errors="replace")[-16384:]}))
        raise RuntimeError("Host command failed: " + Path(argv[0]).name)
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing symlink destination")
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def unpack(archive):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if sum(m.size for m in members) > LIMIT or len({m.name for m in members}) != len(members):
            raise ValueError("Invalid bundle size or duplicate member")
        for member in members:
            p = PurePosixPath(member.name)
            if not member.isfile() or p.is_absolute() or ".." in p.parts or str(p) != member.name:
                raise ValueError("Unsafe bundle member")
        manifest = json.load(tar.extractfile("manifest.json"))
        encoded = json.dumps({k: v for k, v in manifest.items() if k not in ("previous", "revision")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        if manifest.get("revision") != sha(encoded):
            raise ValueError("Bundle manifest revision mismatch")
        expected = {"files/" + p for p in manifest["files"]} | {"manifest.json"}
        if {m.name for m in members} != expected:
            raise ValueError("Unexpected bundle member")
        files = {}
        prefixes = ("etc/reality-proxy-kit/", "etc/systemd/system/", "etc/nginx/", "etc/x-ui/",
                    "opt/reality-proxy-kit/", "usr/local/lib/reality-proxy-kit/", "usr/local/x-ui/", "var/www/reality-proxy-kit/")
        for path, record in manifest["files"].items():
            if not path.startswith(prefixes) or ".." in PurePosixPath(path).parts:
                raise ValueError("Unexpected destination")
            data = tar.extractfile("files/" + path).read()
            if sha(data) != record["sha256"]:
                raise ValueError("Bundle integrity failure")
            files[path] = data
        return manifest, files


def drift(receipt):
    changed = []
    for path, record in receipt["files"].items():
        # Native panel state and generated runtime files have a separate authority.
        if record.get("initial") or path == "etc/reality-proxy-kit/state.json" and receipt["management"] == "panel":
            continue
        destination = Path("/") / path
        if not destination.is_file() or sha(destination.read_bytes()) != record["sha256"]:
            changed.append(path)
    for path, expected in receipt.get("runtime_artifacts", {}).items():
        destination = Path(path)
        if not destination.is_file() or sha(destination.read_bytes()) != expected:
            changed.append(path)
    return changed


def preflight(m):
    if os.geteuid() != 0:
        raise ValueError("Root or noninteractive sudo is required")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if (release.get("ID", "").strip('"'), release.get("VERSION_ID", "").strip('"'), platform.machine()) != ("ubuntu", "24.04", "x86_64"):
        raise ValueError("Only Ubuntu 24.04 amd64 is supported")
    if m.get("environment") not in ("test", "lab"):
        raise ValueError("Candidate installation requires a designated test environment")
    if m.get("machine_id") != Path("/etc/machine-id").read_text().strip():
        raise ValueError("Target machine identity mismatch")
    if (BASE / "transaction.json").exists():
        raise ValueError("Interrupted transaction requires recovery inspection")
    previous = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else None
    if previous:
        if previous["deployment_id"] != m["deployment_id"] or previous["node"] != m["node"]:
            raise ValueError("Host belongs to another deployment")
        if previous["core"]["sha256"] != m["core"]["sha256"]:
            raise ValueError("Core upgrades require a separate reviewed upgrade workflow")
        if drift(previous):
            raise ValueError("Managed files drifted; diagnose before replacing them")
        if previous["revision"] != m.get("previous") and previous["revision"] != m["revision"]:
            raise ValueError("Stale deployment receipt")
        if previous["management"] != m["management"] and not (m.get("adopt") and previous["management"] == "core" and m["management"] == "panel"):
            raise ValueError("Management change requires explicit core-to-panel adoption")
        if previous["revision"] != m["revision"] and previous["role"] == "entry" and previous["management"] == "panel":
            sys.path.insert(0, "/opt/reality-proxy-kit")
            from reality_proxy_kit.model import Deployment
            from reality_proxy_kit.panel import snapshot
            old_spec = Deployment(json.loads((BASE / "deployment.json").read_text()))
            old_state = json.loads((BASE / "state.json").read_text())
            _, _, token = snapshot(old_spec, old_state)
            if not m.get("panel_expected") or token != m["panel_expected"]:
                raise ValueError("Panel changed since the candidate snapshot; refresh before applying")
        return previous
    if m.get("previous"):
        raise ValueError("Expected managed deployment is missing")
    for path in ("/etc/x-ui", "/usr/local/x-ui", "/etc/xray", "/usr/local/etc/xray", "/etc/sing-box", "/etc/nginx"):
        if Path(path).exists():
            raise ValueError("Unmanaged service already exists")
    output = run(["ss", "-H", "-lntup"]).stdout.decode()
    for line in output.splitlines():
        # Blank hosts may run sshd, systemd-resolved and DHCP, but no proxy/web listener.
        if any((":" + str(p) + " ") in line for p in (80, 443, 2096, 2097, 54321, 10085, 24443)):
            raise ValueError("Required listening port is occupied")
    if shutil.which("nft") and run(["nft", "list", "ruleset"]).stdout.strip():
        raise ValueError("Existing firewall rules require an explicit migration")
    if shutil.disk_usage("/").free < 1024**3:
        raise ValueError("At least 1 GiB free space is required")
    return None


def download(pin, filename):
    cache = Path("/var/cache/reality-proxy-kit")
    cache.mkdir(parents=True, mode=0o700, exist_ok=True)
    destination = cache / filename
    if destination.exists() and sha(destination.read_bytes()) == pin["sha256"]:
        return destination
    if not pin["url"].startswith("https://github.com/"):
        raise ValueError("Unexpected dependency download origin")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(pin["url"], timeout=120) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or sha(data) != pin["sha256"]:
        raise ValueError("Dependency checksum mismatch")
    write(destination, data)
    return destination


def upstream_files(archive, panel=False):
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError("Unsafe upstream archive")
            if not member.isfile():
                continue
            if panel:
                # Never extract upstream's bundled Xray or install/update scripts.
                if str(p) == "x-ui/x-ui":
                    write("/usr/local/x-ui/x-ui", tar.extractfile(member).read(), 0o755)
            elif p.name == "sing-box":
                write("/usr/local/bin/sing-box", tar.extractfile(member).read(), 0o755)


def firewall():
    config = (BASE / "firewall.nft").read_text()
    exists = run(["nft", "list", "table", "inet", "rpk"], check=False).returncode == 0
    with tempfile.NamedTemporaryFile(mode="w") as candidate:
        candidate.write(("delete table inet rpk\n" if exists else "") + config)
        candidate.flush()
        run(["nft", "-c", "-f", candidate.name])
        run(["nft", "-f", candidate.name])


def certificates(m):
    web = m["web"]
    if not web.get("enabled"):
        return
    target = BASE / "tls"
    target.mkdir(mode=0o700, exist_ok=True)
    domain = web["domain"]
    if m["environment"] == "lab":
        if not (target / "privkey.pem").exists():
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7", "-subj", "/CN=" + domain,
                 "-addext", "subjectAltName=DNS:" + domain, "-keyout", str(target / "privkey.pem"), "-out", str(target / "fullchain.pem")])
            (target / "privkey.pem").chmod(0o600)
        return
    live = Path("/etc/letsencrypt/live") / domain
    if not live.exists():
        # HTTP-01 only needs port 80. Stop nginx for the initial standalone issuance.
        run(["systemctl", "stop", "nginx"], check=False)
        run(["certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos", "--email", web["acme_email"], "-d", domain])
    for name in ("fullchain.pem", "privkey.pem"):
        write(target / name, (live / name).read_bytes())
    acme = Path("/var/lib/reality-proxy-kit/acme")
    acme.mkdir(parents=True, exist_ok=True, mode=0o755)
    run(["nginx", "-t"])
    run(["systemctl", "start", "nginx"])
    run(["certbot", "reconfigure", "--cert-name", domain, "--webroot", "-w", str(acme), "--non-interactive"])
    hook = "#!/usr/bin/python3\nimport os,pathlib,shutil,subprocess\np=pathlib.Path(os.environ['RENEWED_LINEAGE'])\nif p.name == " + repr(domain) + ":\n for n in ('fullchain.pem','privkey.pem'):\n  t=pathlib.Path('/etc/reality-proxy-kit/tls')/n\n  shutil.copyfile(p/n,t); t.chmod(0o600)\n subprocess.run(['nginx','-t'],check=True)\n subprocess.run(['systemctl','reload','nginx'],check=True)\n"
    write("/etc/letsencrypt/renewal-hooks/deploy/rpk", hook, 0o755)
    run(["systemctl", "enable", "--now", "certbot.timer"])


def services(m):
    result = ["rpk-entry" if m["management"] == "core" else "x-ui"] if m["role"] == "entry" else ["rpk-exit"]
    if m.get("web", {}).get("enabled"):
        result.append("nginx")
    if m.get("subscriptions"):
        result.append("rpk-subscription")
    return result


def verify(m):
    checks = {}
    for unit in services(m):
        checks[unit + "_active"] = run(["systemctl", "is-active", unit], check=False).returncode == 0
    if m["role"] == "entry":
        path = "/usr/local/x-ui/bin/xray-linux-amd64" if m["management"] == "panel" else "/usr/local/lib/reality-proxy-kit/xray"
        checks["disk_core_hash"] = sha(Path(path).read_bytes()) == m["core"]["sha256"]
        matches = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                if str((proc / "exe").resolve()) == path:
                    matches.append(proc)
            except OSError:
                continue
        checks["one_core_process"] = len(matches) == 1
        checks["running_core_hash"] = bool(matches) and all(sha((p / "exe").read_bytes()) == m["core"]["sha256"] for p in matches)
        checks["compatibility_enabled"] = bool(matches) and all(b"UTENASAMA_REALITY_LEGACY_X25519=1" in (p / "environ").read_bytes().split(b"\0") for p in matches)
        checks["identity_routing_enabled"] = bool(matches) and all(b"RPK_VLESS_IDENTITY_ROUTING=1" in (p / "environ").read_bytes().split(b"\0") for p in matches)
    for path, expected in m.get("runtime_artifacts", {}).items():
        checks[Path(path).name + "_disk_hash"] = Path(path).is_file() and sha(Path(path).read_bytes()) == expected
        unit = "rpk-exit" if Path(path).name == "sing-box" else "x-ui"
        pid = run(["systemctl", "show", "-p", "MainPID", "--value", unit]).stdout.decode().strip()
        proc = Path("/proc") / pid / "exe"
        checks[Path(path).name + "_running_hash"] = proc.exists() and sha(proc.read_bytes()) == expected
    checks["firewall_present"] = run(["nft", "list", "table", "inet", "rpk"], check=False).returncode == 0
    return checks


def apply(archive):
    m, files = unpack(archive)
    prior = preflight(m)
    if prior and prior["revision"] == m["revision"]:
        checks = verify(prior)
        if not all(checks.values()):
            raise ValueError("Existing deployment is unhealthy; diagnose before reapplying")
        return {"status": "unchanged", "revision": m["revision"], "checks": checks}
    BASE.mkdir(mode=0o700, exist_ok=True)
    BASE.chmod(0o750)
    lock = open(BASE / "operation.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Re-check after acquiring the lock, including the optimistic receipt.
    prior = preflight(m)
    backup = Path("/var/lib/reality-proxy-kit/transactions") / m["revision"]
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    write(BASE / "transaction.json", json.dumps({"revision": m["revision"], "phase": "packages"}))
    previous_files, written = {}, []
    try:
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
        run(["apt-get", "update", "-qq"])
        packages = ["ca-certificates", "nftables", "python3-cryptography", "python3-yaml"]
        if m.get("web", {}).get("enabled"):
            packages += ["nginx", "libnginx-mod-stream", "certbot", "openssl"]
        run(["apt-get", "install", "-y", "-qq", *packages])
        if not any(u.pw_name == "rpk" for u in pwd.getpwall()):
            run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "rpk"])
        if m["role"] == "exit":
            upstream_files(download(m["pins"]["sing_box"], "sing-box.tar.gz"))
        elif m["management"] == "panel" and (not prior or prior["management"] == "core"):
            upstream_files(download(m["pins"]["panel"], "panel.tar.gz"), panel=True)
        artifact = "/usr/local/bin/sing-box" if m["role"] == "exit" else "/usr/local/x-ui/x-ui" if m["management"] == "panel" else None
        m["runtime_artifacts"] = {artifact: sha(Path(artifact).read_bytes())} if artifact else {}
        if m.get("adopt"):
            run(["systemctl", "stop", "rpk-entry"])
        for path, record in m["files"].items():
            dest = Path("/") / path
            if record.get("initial") and dest.exists() and not m.get("adopt") and not (path == "etc/reality-proxy-kit/state.json" and m.get("panel_expected")):
                if path == "etc/x-ui/x-ui.db":
                    raise ValueError("Cannot restore a database over an existing panel")
                continue
            if dest.exists():
                st = dest.stat()
                previous_files[path] = {"mode": st.st_mode & 0o777, "uid": st.st_uid, "gid": st.st_gid, "data": dest.read_bytes()}
                write(backup / path, previous_files[path]["data"], previous_files[path]["mode"])
            write(dest, files[path], record["mode"])
            written.append(path)
            if record["mode"] == 0o640:
                shutil.chown(dest, group="rpk")
        shutil.chown(BASE, group="rpk")
        sys.path.insert(0, "/opt/reality-proxy-kit")
        run(["systemctl", "daemon-reload"])
        firewall()
        run(["systemctl", "enable", "rpk-firewall"])
        if m["role"] == "exit":
            run(["sing-box", "check", "-c", str(BASE / "sing-box.json")])
        elif m["management"] == "core":
            run(["/usr/local/lib/reality-proxy-kit/xray", "run", "-test", "-c", str(BASE / "xray.json")])
        else:
            from reality_proxy_kit.model import Deployment
            from reality_proxy_kit import panel
            spec, state = Deployment(json.loads((BASE / "deployment.json").read_text())), json.loads((BASE / "state.json").read_text())
            fresh_panel = not prior or prior["management"] == "core"
            if fresh_panel and not m.get("restore"):
                panel.prepare(spec, state)
            run(["systemctl", "enable", "--now", "x-ui"])
            for attempt in range(20):
                try:
                    api = panel.API(state["panel"])
                    break
                except Exception:
                    if attempt == 19:
                        raise RuntimeError("Panel did not become ready") from None
                    time.sleep(1)
            panel.publish(spec, state, api, initial=fresh_panel and not m.get("restore"))
        certificates(m)
        if m.get("web", {}).get("enabled"):
            run(["nginx", "-t"])
        for service in services(m):
            run(["systemctl", "enable", service])
            run(["systemctl", "restart", service])
        for attempt in range(15):
            checks = verify(m)
            if all(checks.values()):
                break
            time.sleep(1)
        if not all(checks.values()):
            raise ValueError("Post-install service or running core verification failed")
        if m.get("adopt"):
            run(["systemctl", "disable", "rpk-entry"])
        write(RECEIPT, json.dumps(m, indent=2))
        (BASE / "transaction.json").unlink()
        return {"status": "applied", "revision": m["revision"], "checks": checks, "network_acceptance": "pending"}
    except Exception:
        import traceback
        write(BASE / "last-operation-error.json", json.dumps({"traceback": traceback.format_exc()}))
        for service in services(m):
            run(["systemctl", "stop", service], check=False)
        for path in reversed(written):
            dest = Path("/") / path
            if path in previous_files:
                record = previous_files[path]
                write(dest, record["data"], record["mode"])
                os.chown(dest, record["uid"], record["gid"])
            elif dest.is_file():
                dest.unlink()
        run(["systemctl", "daemon-reload"], check=False)
        if prior:
            firewall()
            for service in services(prior):
                run(["systemctl", "start", service], check=False)
        recovered = verify(prior) if prior else {}
        write(BASE / "transaction.json", json.dumps({"revision": m["revision"], "phase": "failed", "files_restored": True,
                                                    "previous_service_checks": recovered,
                                                    "os_packages_certificates_native_db": "inspect before recovery"}))
        raise
    finally:
        lock.close()


def main():
    try:
        if sys.argv[1] == "apply":
            result = apply(sys.argv[2])
        elif sys.argv[1] == "preflight":
            m, _ = unpack(sys.argv[2]); preflight(m)
            result = {"preflight": "passed"}
        elif sys.argv[1] == "firewall":
            firewall(); result = {"firewall": "loaded"}
        elif sys.argv[1] == "diagnose":
            if not RECEIPT.exists():
                result = {"managed": False, "interrupted_transaction": (BASE / "transaction.json").exists()}
            else:
                m = json.loads(RECEIPT.read_text())
                result = {"managed": True, "checks": verify(m), "drift_count": len(drift(m)), "network_acceptance": "not tested by diagnose"}
        else:
            raise ValueError("Unknown remote operation")
        print(json.dumps(result))
    except Exception as exc:
        # Do not echo subprocess output, command arguments, or database values.
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc) if isinstance(exc, ValueError) else "Host operation failed; inspect private host diagnostics"}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
