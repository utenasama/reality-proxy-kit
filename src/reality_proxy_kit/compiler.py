"""Create immutable, secret-bearing per-node bundles without networking."""
import copy
import io
import json
import ipaddress
from pathlib import Path
import tarfile
from . import config
from .files import atomic_write, canonical, digest, private_directory, read_json, revision, write_json
from .state import validate

ROOT = Path(__file__).resolve().parents[2]


def firewall(deployment, node_id):
    node = deployment.nodes[node_id]
    allowed = ["iifname lo accept", "ct state established,related accept", "ct state invalid drop",
               "ip protocol icmp accept", "meta l4proto ipv6-icmp accept",
               "tcp dport " + str(node.get("ssh", {}).get("port", 22)) + " accept"]
    if node_id == deployment.entry_id:
        allowed += ["tcp dport 443 accept"]
        if deployment.data.get("web", {}).get("enabled"):
            allowed += ["tcp dport 80 accept"]
    else:
        for proto in ("tcp", "udp"):
            allowed += ["ip saddr " + deployment.entry["ipv4"] + " " + proto + " dport " + str(node.get("proxy_port", 24443)) + " accept"]
    return "table inet rpk {\n chain input { type filter hook input priority 0; policy drop;\n  " + ";\n  ".join(allowed) + ";\n }\n chain output { type filter hook output priority 0; policy accept;\n  meta mark 48211 ip daddr { " + ", ".join(config.PRIVATE_V4) + " } reject;\n  meta mark 48211 meta nfproto ipv6 reject;\n }\n}\n"


def plan(deployment, state):
    validate(state, deployment)
    missing = []
    for node_id, node in deployment.nodes.items():
        for field in ("key_file", "known_hosts", "machine_id"):
            if not node.get("ssh", {}).get(field):
                missing.append(node_id + ":ssh." + field)
        if deployment.data.get("environment") != "lab" and not ipaddress.ip_address(node["ipv4"]).is_global:
            missing.append(node_id + ":public_ipv4")
    if deployment.data["reality"].get("target", "").split(":")[0] in ("www.example.com", "example.com"):
        missing.append("reality.target:replace_placeholder_and_verify_tls")
    return {"schema": 1, "mode": deployment.data["mode"], "management": state["management"],
            "deployable": not missing, "missing_inputs": missing,
            "order": [*deployment.exits, deployment.entry_id], "restarts": True,
            "routes": [{"id": rid, "number": r["number"], "exit": r["exit"]} for rid, r in deployment.active_routes.items()],
            "nodes": [{"id": n, "role": v["role"], "public_tcp": [443] + ([80] if deployment.data.get("web", {}).get("enabled") else []) if n == deployment.entry_id else [],
                       "entry_only_tcp_udp": v.get("proxy_port", 24443) if n != deployment.entry_id else None,
                       "ssh_tcp": v.get("ssh", {}).get("port", 22)} for n, v in deployment.nodes.items()],
            "admin": "SSH tunnel to 127.0.0.1:54321" if state["management"] == "panel" else None,
            "rollback_scope": "managed files and services; OS packages, issued certificates and database API transactions are separate"}


def compile_bundle(deployment, state, output, binary, build_manifest, receipts=None, restore_db=None, adopt=False):
    validate(state, deployment)
    binary, output = Path(binary), Path(output)
    manifest = read_json(build_manifest)
    expected = read_json(ROOT / "manifests/core-candidate.json")
    for key in ("sha256", "xray", "reality", "target", "compatibility_env", "identity_env", "traffic_observer"):
        if manifest.get(key) != expected.get(key):
            raise ValueError("Core does not match the reviewed candidate manifest")
    if digest(binary.read_bytes()) != manifest["sha256"]:
        raise ValueError("Core binary checksum mismatch")
    if deployment.data.get("environment", "production") == "production":
        raise ValueError("No accepted installable release exists yet; use a designated test environment")
    if output.exists():
        raise ValueError("Render into a new private directory")
    private_directory(output)
    pins = read_json(ROOT / "manifests/upstream.json")
    public_spec = copy.deepcopy(deployment.data)
    for n in public_spec["nodes"].values():
        n.pop("ssh", None)
    public_spec.get("web", {}).pop("static_dir", None)
    result = {}
    for node_id, node in deployment.nodes.items():
        files = {}
        def add(path, data, mode=0o600, initial=False):
            if not isinstance(data, bytes):
                data = data.encode() if isinstance(data, str) else canonical(data) + b"\n"
            files[path] = {"data": data, "sha256": digest(data), "mode": mode, "initial": initial}
        entry = node_id == deployment.entry_id
        add("etc/reality-proxy-kit/firewall.nft", firewall(deployment, node_id))
        add("etc/systemd/system/rpk-firewall.service", "[Unit]\nDescription=Reality Proxy Kit firewall\nBefore=rpk-entry.service rpk-exit.service x-ui.service\nAfter=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /opt/reality-proxy-kit/reality_proxy_kit/remote.py firewall\n[Install]\nWantedBy=multi-user.target\n", 0o644)
        for path in sorted((ROOT / "src/reality_proxy_kit").glob("*.py")):
            add("opt/reality-proxy-kit/reality_proxy_kit/" + path.name, path.read_bytes(), 0o644)
        if entry:
            add("etc/reality-proxy-kit/deployment.json", public_spec)
            add("etc/reality-proxy-kit/state.json", state, initial=state["management"] == "panel")
            core_path = "usr/local/x-ui/bin/xray-linux-amd64" if state["management"] == "panel" else "usr/local/lib/reality-proxy-kit/xray"
            add(core_path, binary.read_bytes(), 0o755)
            if state["management"] == "core":
                add("etc/reality-proxy-kit/xray.json", config.entry_config(deployment, state), 0o640)
                add("etc/systemd/system/rpk-entry.service", config.core_unit(), 0o644)
            else:
                add("etc/systemd/system/x-ui.service", "[Unit]\nDescription=3x-ui managed by Reality Proxy Kit\nAfter=network-online.target rpk-firewall.service\n[Service]\nUMask=0077\nWorkingDirectory=/usr/local/x-ui\nEnvironment=UTENASAMA_REALITY_LEGACY_X25519=1\nEnvironment=RPK_VLESS_IDENTITY_ROUTING=1\nExecStart=/usr/local/x-ui/x-ui\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n", 0o644)
                if restore_db:
                    add("etc/x-ui/x-ui.db", Path(restore_db).read_bytes(), initial=True)
                if deployment.data.get("subscriptions"):
                    add("etc/systemd/system/rpk-subscription.service", "[Unit]\nDescription=Reality Proxy Kit native subscription filter\nAfter=x-ui.service\n[Service]\nWorkingDirectory=/opt/reality-proxy-kit\nExecStart=/usr/bin/python3 -m reality_proxy_kit.bridge\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n[Install]\nWantedBy=multi-user.target\n", 0o644)
            nginx = config.nginx_config(deployment)
            if nginx:
                add("etc/nginx/nginx.conf", nginx, 0o644)
                static = Path(deployment.data["web"].get("static_dir", ROOT / "templates/site"))
                if not static.is_dir():
                    raise ValueError("Static website directory not found")
                for path in sorted(static.rglob("*")):
                    if path.is_symlink():
                        raise ValueError("Static content must not contain symlinks")
                    if path.is_file():
                        if any(p.startswith(".") for p in path.relative_to(static).parts):
                            raise ValueError("Hidden files are not published")
                        add("var/www/reality-proxy-kit/" + str(path.relative_to(static)), path.read_bytes(), 0o644)
        else:
            add("etc/reality-proxy-kit/sing-box.json", config.exit_config(deployment, state, node_id), 0o640)
            add("etc/systemd/system/rpk-exit.service", config.exit_unit(), 0o644)
        metadata = {"schema": 1, "deployment_id": state["deployment_id"], "node": node_id, "role": node["role"],
                    "spec_revision": revision(deployment.data), "state_revision": revision(state),
                    "panel_expected": state.get("panel_revision"),
                    "management": state["management"], "environment": deployment.data.get("environment", "production"),
                    "machine_id": node.get("ssh", {}).get("machine_id"), "pins": pins, "core": manifest,
                    "previous": (receipts or {}).get(node_id), "adopt": adopt, "restore": bool(restore_db),
                    "web": public_spec.get("web", {}) if entry else {},
                    "subscriptions": bool(entry and deployment.data.get("subscriptions")),
                    "files": {p: {k: v for k, v in f.items() if k != "data"} for p, f in files.items()}}
        metadata["revision"] = revision({k: v for k, v in metadata.items() if k != "previous"})
        archive = output / (node_id + ".tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            for path, data in [("manifest.json", canonical(metadata)), *[("files/" + p, f["data"]) for p, f in files.items()]]:
                info = tarfile.TarInfo(path)
                info.size, info.mode = len(data), 0o600
                tar.addfile(info, io.BytesIO(data))
        archive.chmod(0o600)
        result[node_id] = {"file": archive.name, "sha256": digest(archive.read_bytes()), "revision": metadata["revision"]}
    write_json(output / "plan.json", plan(deployment, state))
    write_json(output / "bundles.json", result)
    return result
