#!/usr/bin/env python3
"""Disposable Ubuntu/systemd integration; never reads production inventory."""
import base64
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
from reality_proxy_kit import client
from reality_proxy_kit.files import read_json, write_json
from reality_proxy_kit.model import Deployment

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "private/ci-lab"
CORE = Path(os.environ.get("RPK_CORE_DIR", ROOT / "build/core-final"))
PREFIX = "rpk-lab-"
CREATED = []


def run(*args, check=True, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError("Lab command failed: " + str(args[0]))
    return result.stdout if check else result


def docker(node, *args, **kwargs):
    return run("docker", "exec", "-i", PREFIX + node, *args, **kwargs)


def cli(*args):
    result = subprocess.run([sys.executable, "-m", "reality_proxy_kit.cli", *map(str, args)], capture_output=True)
    if result.returncode:
        print(result.stderr.decode(errors="replace")[-1200:], flush=True)
        raise RuntimeError("Controller operation failed")
    return json.loads(result.stdout)


def redact(text):
    values = []
    def collect(value):
        if isinstance(value, dict):
            for v in value.values(): collect(v)
        elif isinstance(value, list):
            for v in value: collect(v)
        elif isinstance(value, str) and len(value) >= 8:
            values.append(value)
    for path in LAB.rglob("state.json"):
        collect(read_json(path))
    for value in sorted(set(values), key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return re.sub(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "[uuid]", text)


def failure_details():
    for node in CREATED:
        if node == "target":
            continue
        result = docker(node, "journalctl", "--no-pager", "-n", "55", "-u", "rpk-entry", "-u", "rpk-exit", "-u", "x-ui", "-u", "rpk-subscription", check=False)
        print(node + ": " + redact(result.stdout.decode(errors="replace"))[-5000:], flush=True)
        for filename in ("last-command-error.json", "last-operation-error.json"):
            result = docker(node, "cat", "/etc/reality-proxy-kit/" + filename, check=False)
            if result.returncode == 0:
                print(redact(result.stdout.decode(errors="replace"))[-3500:], flush=True)


def start_node(name, address):
    run("docker", "run", "-d", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock",
        "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--network", PREFIX + "net", "--ip", address,
        "--add-host", "remote.example.org:192.0.2.2", "--name", PREFIX + name, "rpk-test-host")
    CREATED.append(name)
    for attempt in range(40):
        if docker(name, "systemctl", "is-active", "ssh", check=False).returncode == 0:
            break
        time.sleep(1)
    docker(name, "mkdir", "-p", "/root/.ssh")
    docker(name, "python3", "-c", "import pathlib,sys;p=pathlib.Path('/root/.ssh');p.chmod(0o700);f=p/'authorized_keys';f.write_bytes(sys.stdin.buffer.read());f.chmod(0o600)", input=(LAB / "ssh.pub").read_bytes())
    key = docker(name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").decode().split()
    with (LAB / "known_hosts").open("a") as f:
        f.write(address + " " + " ".join(key[:2]) + "\n")
    return {"address": address, "user": "root", "port": 22, "key_file": str(LAB / "ssh"),
            "known_hosts": str(LAB / "known_hosts"), "machine_id": docker(name, "cat", "/etc/machine-id").decode().strip()}


def udp_dns():
    with socket.create_connection(("127.0.0.1", 17808), timeout=10) as control:
        control.sendall(b"\x05\x01\x00"); assert control.recv(2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01" + b"\0" * 6)
        reply = control.recv(10); assert reply[:4] == b"\x05\x00\x00\x01"
        address, port = socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0]
        query = b"\x71\x23\x01\x00\x00\x01" + b"\0" * 6 + b"\x04test\x07example\x03org\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.sendto(b"\0\0\0\x01" + socket.inet_aton("192.0.2.2") + struct.pack("!H", 53) + query, (address, port))
            response, _ = sock.recvfrom(4096)
            assert response[10:12] == b"\x71\x23" and response[12] & 128


def probe(node, expected, name, success=True, fingerprint="chrome", checks=True):
    profile = client.xray_profile(node, fingerprint=fingerprint)
    profile["log"]["loglevel"] = "debug"
    path = LAB / (name + "-client.json"); write_json(path, profile)
    with (LAB / (name + "-client.log")).open("wb") as log:
        process = subprocess.Popen([str(CORE / "xray-linux-amd64"), "run", "-c", str(path)], stdout=log, stderr=log)
        try:
            time.sleep(1)
            response = run("curl", "--noproxy", "", "--socks5-hostname", "127.0.0.1:17808", "-kfsS", "--http1.1", "--max-time", "12", "https://test.example.org/", check=False)
            if not success:
                assert response.returncode != 0, "A denied route unexpectedly connected"
                return
            if response.returncode:
                print("curl: " + redact(response.stderr.decode(errors="replace")), flush=True)
                print("client: " + redact((LAB / (name + "-client.log")).read_text())[-2500:], flush=True)
                raise AssertionError("Expected HTTPS route failed")
            result = json.loads(response.stdout)
            assert result["peer"] == expected, "Wrong exit address"
            assert any(q["source"] == expected and q["name"] == "test.example.org" for q in result["dns"]), "Domain did not resolve at final exit"
            if not checks:
                return
            udp_dns()
            for target in ("http://127.0.0.1:8000/", "http://private.example.org:8000/", "http://[::1]:8000/"):
                rejected = run("curl", "--noproxy", "", "--socks5-hostname", "127.0.0.1:17808", "-fsS", "--max-time", "5", target, check=False)
                assert rejected.returncode != 0, "Forbidden destination was reachable"
        finally:
            process.terminate(); process.wait(timeout=10)


def case(mode, management, target):
    label = "-".join((mode, management, target))
    print(label + ": preparing", flush=True)
    nodes = {"entry": {"role": "entry", "ipv4": "192.0.2.11", "ssh": start_node("entry", "192.0.2.11")}}
    routes = {"direct-v1": {"number": 1, "exit": "direct", "label": "Direct"}}
    if mode == "chain":
        for name, address in (("exit-a", "192.0.2.12"), ("exit-b", "192.0.2.13")):
            nodes[name] = {"role": "exit", "ipv4": address, "proxy_port": 24443, "ssh": start_node(name, address)}
        routes = {"route-a": {"number": 101, "exit": "exit-a", "label": "Exit A"}, "route-b": {"number": 102, "exit": "exit-b", "label": "Exit B"}}
    spec = {"schema": 1, "environment": "lab", "mode": mode, "management": management, "entry_id": "entry", "nodes": nodes, "routes": routes,
            "dns_ipv4": "192.0.2.2", "web": {"enabled": target == "local" or management == "panel", "domain": "site.example.org"},
            "subscriptions": management == "panel", "reality": {"target_mode": target, "server_names": ["site.example.org" if target == "local" else "remote.example.org"]}}
    if target == "remote": spec["reality"]["target"] = "remote.example.org:443"
    folder = LAB / label; folder.mkdir(mode=0o700)
    spec_path, state_path, receipts = folder / "spec.json", folder / "state.json", folder / "receipts.json"
    write_json(spec_path, spec)
    common = ["--spec", spec_path, "--state", state_path]
    cli("init", *common, "--account", "alice", "--account", "bob")
    cli("render", *common, "--core", CORE / "xray-linux-amd64", "--core-manifest", CORE / "build-manifest.json", "--output", folder / "bundle")
    apply_args = ["apply", *common, "--bundle", folder / "bundle", "--receipts", receipts, "--backup-dir", folder / "backups", "--key", folder / "key/backup.key"]
    cli(*apply_args)
    repeated = cli(*apply_args)
    assert all(v["status"] == "unchanged" for v in repeated["nodes"].values())
    state = read_json(state_path); dep = Deployment(spec)
    entries = client.nodes(dep, state, state["accounts"][0])
    for n in entries:
        route = routes[n["route"]]
        probe(n, nodes[route["exit"]]["ipv4"] if mode == "chain" else nodes["entry"]["ipv4"], label)
    wrong = dict(entries[0], uuid=client.route_uuid(state["accounts"][0]["uuid"], 65534))
    probe(wrong, None, label, False)
    if mode == "single" and management == "core" and target == "remote":
        for fingerprint in ("hellochrome_120", "hellosafari_26_3"):
            probe(entries[0], nodes["entry"]["ipv4"], label, fingerprint=fingerprint, checks=False)
        import uuid
        wrong_account = dict(entries[0], uuid=client.route_uuid(str(uuid.uuid4()), 1))
        probe(wrong_account, None, label, False)
        wrong_short_id = dict(entries[0], short_id="00" * 8 if entries[0]["short_id"] != "00" * 8 else "11" * 8)
        probe(wrong_short_id, None, label, False, fingerprint="hellochrome_120")
        for operation in ("disable", "enable"):
            cli("account", operation, "alice", *common, "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
            bundle = folder / ("bundle-" + operation)
            cli("render", *common, "--core", CORE / "xray-linux-amd64", "--core-manifest", CORE / "build-manifest.json",
                "--receipts", receipts, "--output", bundle)
            cli("apply", *common, "--bundle", bundle, "--receipts", receipts,
                "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
            probe(entries[0], nodes["entry"]["ipv4"], label, operation == "enable", checks=False)
    if mode == "chain":
        docker("exit-a", "systemctl", "stop", "rpk-exit")
        probe(entries[0], None, label, False)
        probe(entries[1], "192.0.2.13", label)
        docker("exit-a", "systemctl", "start", "rpk-exit")
    if spec["web"]["enabled"]:
        def web(path):
            return run("curl", "--noproxy", "*", "-kfsS", "--http1.1", "--max-time", "15", "--resolve", "site.example.org:443:192.0.2.11", "https://site.example.org" + path, check=False)
        assert web("/").returncode == 0
        assert web("/admin/").returncode != 0
        if management == "panel":
            for kind in ("s", "m", "x"):
                response = web("/" + kind + "/" + state["accounts"][0]["sub_id"])
                assert response.returncode == 0, "Filtered native subscription failed"
                if kind == "s":
                    body = response.stdout if response.stdout.startswith(b"vless://") else base64.b64decode(response.stdout)
                    assert b"fp=" not in body and b"fingerprint=" not in body
                if kind == "x":
                    profiles = json.loads(response.stdout)
                    for index, profile in enumerate(profiles if isinstance(profiles, list) else [profiles]):
                        path = folder / ("native-xray-" + str(index) + ".json"); write_json(path, profile)
                        validation = run(CORE / "xray-linux-amd64", "run", "-test", "-c", path, check=False)
                        if validation.returncode:
                            print(redact(validation.stderr.decode(errors="replace")), flush=True)
                            raise AssertionError("Native Xray subscription did not validate")
            cli("account", "disable", "alice", *common, "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
            probe(entries[0], None, label, False)
            if mode == "chain" and target == "remote":
                def account(operation, *extra):
                    cli("account", operation, "alice", *extra, *common, "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
                    latest = read_json(state_path)
                    return latest, next((a for a in latest["accounts"] if a["name"] == "alice"), None)
                account("enable")
                probe(entries[0], "192.0.2.12", label, checks=False)
                account("grant", "--routes", "route-b")
                probe(entries[0], None, label, False)
                probe(entries[1], "192.0.2.13", label, checks=False)
                latest, rotated = account("rotate")
                assert rotated["id"] == state["accounts"][0]["id"]
                assert web("/s/" + state["accounts"][0]["sub_id"]).returncode != 0
                assert web("/s/" + rotated["sub_id"]).returncode == 0
                probe(entries[1], None, label, False)
                rotated_nodes = client.nodes(dep, latest, rotated)
                probe(rotated_nodes[0], "192.0.2.13", label, checks=False)
                account("delete")
                probe(rotated_nodes[0], None, label, False)
                latest, recreated = account("add", "--routes", "route-a")
                assert recreated["id"] != rotated["id"]
                assert recreated["routes"] == ["route-a"]
                probe(client.nodes(dep, latest, recreated)[0], "192.0.2.12", label, checks=False)
                saved = cli("backup", "--live", *common, "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
                restored = folder / "restored"
                cli("restore", "--archive", saved["file"], "--key", folder / "key/backup.key", "--output", restored)
                before_restore = read_json(restored / "state.json")
                print(label + ": restoring a blank entry", flush=True)
                # Replace only this disposable entry, keeping both exits alive.
                run("docker", "rm", "-f", PREFIX + "entry"); CREATED.remove("entry")
                trust = LAB / "known_hosts"
                trust.write_text("".join(line for line in trust.read_text().splitlines(True) if not line.startswith("192.0.2.11 ")))
                restored_spec = read_json(restored / "deployment.json")
                restored_spec["nodes"]["entry"]["ssh"] = start_node("entry", "192.0.2.11")
                restored_spec["web"]["static_dir"] = str(restored / "site")
                write_json(restored / "deployment.json", restored_spec)
                old_receipts = read_json(receipts); old_receipts.pop("entry")
                restore_receipts = restored / "receipts.json"; write_json(restore_receipts, old_receipts)
                common = ["--spec", restored / "deployment.json", "--state", restored / "state.json"]
                cli("render", *common, "--core", CORE / "xray-linux-amd64", "--core-manifest", CORE / "build-manifest.json",
                    "--receipts", restore_receipts, "--restore-db", restored / "panel.db", "--output", restored / "bundle")
                cli("apply", *common, "--bundle", restored / "bundle", "--receipts", restore_receipts,
                    "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
                cli("refresh", *common, "--output", restored / "verified-state.json")
                after_restore = read_json(restored / "verified-state.json")
                for field in ("accounts", "reality", "links", "route_registry", "deployment_id"):
                    assert before_restore[field] == after_restore[field], "Restore changed stable identities"
                probe(client.nodes(dep, latest, recreated)[0], "192.0.2.12", label, checks=False)
                assert web("/s/" + recreated["sub_id"]).returncode == 0
    if mode == "single" and management == "core" and target == "local":
        adopted_spec = dict(spec, management="panel", subscriptions=False)
        adopted_spec_path, adopted_state_path = folder / "adopt-spec.json", folder / "adopt-state.json"
        write_json(adopted_spec_path, adopted_spec)
        cli("adopt", *common, "--new-spec", adopted_spec_path, "--output", adopted_state_path,
            "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
        common = ["--spec", adopted_spec_path, "--state", adopted_state_path]
        cli("render", *common, "--core", CORE / "xray-linux-amd64", "--core-manifest", CORE / "build-manifest.json",
            "--receipts", receipts, "--adopt", "--output", folder / "adopt-bundle")
        cli("apply", *common, "--bundle", folder / "adopt-bundle", "--receipts", receipts,
            "--backup-dir", folder / "backups", "--key", folder / "key/backup.key")
        probe(entries[0], "192.0.2.11", label, checks=False)
        assert web("/s/" + state["accounts"][0]["sub_id"]).returncode != 0
    cli("diagnose", *common, "--output", folder / "diagnostic.json")
    print(label + ": passed integration checks", flush=True)


def clean_nodes():
    for name in list(CREATED):
        if name != "target":
            run("docker", "rm", "-f", PREFIX + name, check=False)
            CREATED.remove(name)


def main():
    cases = [(mode, management, target) for mode in ("single", "chain")
             for management in ("core", "panel") for target in ("remote", "local")]
    selected = os.environ.get("RPK_LAB_CASE")
    if selected:
        cases = [c for c in cases if "-".join(c) == selected]
        if not cases:
            raise SystemExit("Unknown isolated lab case")
    if LAB.exists():
        raise SystemExit("Use a clean disposable lab directory")
    LAB.mkdir(parents=True, mode=0o700)
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", LAB / "ssh")
    run("docker", "build", "-t", "rpk-test-host", ROOT / "tests/lab")
    run("docker", "network", "create", "--subnet", "192.0.2.0/24", PREFIX + "net")
    try:
        run("docker", "run", "-d", "--network", PREFIX + "net", "--ip", "192.0.2.2", "--name", PREFIX + "target", "-v", str(ROOT / "tests/lab") + ":/test:ro", "rpk-test-host", "python3", "/test/target.py")
        CREATED.append("target"); time.sleep(3)
        for mode, management, target in cases:
            try:
                case(mode, management, target)
            except Exception:
                failure_details()
                raise
            finally:
                clean_nodes()
    finally:
        for name in CREATED:
            run("docker", "rm", "-f", PREFIX + name, check=False)
        run("docker", "network", "rm", PREFIX + "net", check=False)


if __name__ == "__main__":
    main()
