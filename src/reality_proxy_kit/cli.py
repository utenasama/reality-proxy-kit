"""Controller CLI. All credential-bearing output goes to private files."""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import sys
import time
from . import backup, client, compiler, state as identities
from .files import canonical, digest, private_directory, read_json, require_private_output, revision, write_json
from .model import Deployment
from .transport import SSH

ROOT = Path(__file__).resolve().parents[2]


def private(path):
    return require_private_output(path, ROOT)


def load(args):
    spec = Deployment.read(args.spec)
    state = read_json(args.state)
    identities.validate(state, spec)
    return spec, state


def remote_snapshot(spec):
    ssh = SSH(spec.entry)
    ssh.probe()
    return json.loads(ssh.run(["env", "PYTHONPATH=/opt/reality-proxy-kit", "python3", "-m", "reality_proxy_kit.maintenance"], canonical({"action": "snapshot"})))


def save_backup(spec, state, args, live=False):
    extra = {}
    if live or state["management"] == "panel":
        snapshot = remote_snapshot(spec)
        if snapshot["state"]["deployment_id"] != state["deployment_id"]:
            raise ValueError("Remote state belongs to another deployment")
        state = snapshot["state"]
        old_spec = copy.deepcopy(snapshot["deployment"])
        for node_id, node in old_spec["nodes"].items():
            if node_id in spec.nodes and "ssh" in spec.nodes[node_id]:
                node["ssh"] = spec.nodes[node_id]["ssh"]
        spec = Deployment(old_spec)
        extra = {p: base64.b64decode(data) for p, data in snapshot["files"].items()}
    directory = private(args.backup_dir)
    private_directory(directory)
    name = "snapshot-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3) + ".rpk"
    result = backup.create(spec.data, state, directory / name, private(args.key), extra)
    return {"file": str(directory / name), **result}


def execute(args):
    if args.command == "restore":
        return backup.restore(args.archive, args.key, private(args.output))
    spec, state = (Deployment.read(args.spec), None) if args.command == "init" else load(args)
    if args.command == "init":
        path = private(args.state)
        private_directory(path.parent)
        state = identities.initialize(spec, args.account)
        write_json(path, state, exclusive=True)
        return {"initialized": True, "management": state["management"], "accounts": len(state["accounts"]), "state": str(path)}
    if args.command == "plan":
        return compiler.plan(spec, state)
    if args.command == "render":
        receipts = read_json(args.receipts) if args.receipts and Path(args.receipts).exists() else {}
        return compiler.compile_bundle(spec, state, private(args.output), args.core, args.core_manifest, receipts,
                                       restore_db=args.restore_db, adopt=args.adopt)
    if args.command == "export":
        if state["management"] == "panel":
            state = remote_snapshot(spec)["state"]
        return client.export(spec, state, args.account, private(args.output))
    if args.command == "backup":
        return save_backup(spec, state, args, live=args.live)
    if args.command == "snapshot":
        result = remote_snapshot(spec)
        write_json(private(args.output), result, exclusive=True)
        return {"snapshot_saved": True, "sensitive": True}
    if args.command == "refresh":
        result = remote_snapshot(spec)
        fresh = result["state"]
        if fresh["management"] == "panel":
            fresh["panel_revision"] = result["token"]
        write_json(private(args.output), fresh, exclusive=True)
        return {"state_saved": True, "sensitive": True, "next": "use the refreshed state for a new render"}
    if args.command == "account":
        if state["management"] == "panel":
            before = remote_snapshot(spec)
            saved = backup.create(spec.data, before["state"], private(args.backup_dir) / ("before-account-" + secrets.token_hex(5) + ".rpk"),
                                  private(args.key), {p: base64.b64decode(v) for p, v in before["files"].items()})
            request = {"action": "account", "operation": args.operation, "name": args.name, "routes": args.routes, "expected": before["token"]}
            result = json.loads(SSH(spec.entry).run(["env", "PYTHONPATH=/opt/reality-proxy-kit", "python3", "-m", "reality_proxy_kit.maintenance"], canonical(request)))
            write_json(args.state, remote_snapshot(spec)["state"])
            return result
        save_backup(spec, state, args)
        updated = identities.locked_update(args.state, revision(state), lambda current: identities.mutate(current, spec, args.operation, args.name, args.routes))
        return {"generation": updated["generation"], "server_changed": False, "next": "render and apply the new plan"}
    if args.command in ("topology", "adopt"):
        new = Deployment.read(args.new_spec)
        saved = save_backup(spec, state, args)
        if state["management"] == "panel":
            snapshot = remote_snapshot(spec)
            candidate = snapshot["state"]
            candidate["panel_revision"] = snapshot["token"]
        else:
            candidate = copy.deepcopy(state)
        if args.command == "adopt":
            if new.data["management"] != "panel":
                raise ValueError("Adoption requires a panel specification")
            candidate["management"] = "panel"
        candidate = identities.reconcile(candidate, new)
        write_json(private(args.output), candidate, exclusive=True)
        return {"candidate_saved": True, "backup": saved, "server_changed": False, "next": "render the new spec; adoption additionally needs render --adopt"}
    if args.command == "diagnose":
        results = {}
        for node_id in args.node or spec.nodes:
            if node_id not in spec.nodes:
                raise ValueError("Unknown node")
            ssh = SSH(spec.nodes[node_id]); ssh.probe()
            results[node_id] = json.loads(ssh.run(["python3", "/opt/reality-proxy-kit/reality_proxy_kit/remote.py", "diagnose"]))
        write_json(private(args.output), results, exclusive=True)
        return {"report": str(Path(args.output).resolve()), "nodes": len(results), "redacted": True}
    if args.command == "apply":
        output = Path(args.bundle)
        bundles = read_json(output / "bundles.json")
        receipts = read_json(args.receipts) if Path(args.receipts).exists() else {}
        if set(bundles) != set(spec.nodes):
            raise ValueError("Bundle nodes do not match the deployment")
        # Probe every target and validate every bundle before changing any node.
        from .remote import unpack
        connections, remote_paths = {}, {}
        results = {}
        try:
            for node_id, record in bundles.items():
                archive = output / record["file"]
                if digest(archive.read_bytes()) != record["sha256"]:
                    raise ValueError("Bundle archive hash mismatch")
                manifest, _ = unpack(archive)
                if manifest["deployment_id"] != state["deployment_id"] or manifest["machine_id"] != spec.nodes[node_id].get("ssh", {}).get("machine_id"):
                    raise ValueError("Bundle identity does not match the current spec")
                if (manifest["node"], manifest["role"], manifest["management"], manifest["environment"]) != (node_id, spec.nodes[node_id]["role"], state["management"], spec.data.get("environment", "production")):
                    raise ValueError("Bundle role or environment differs from the deployment")
                approved = read_json(ROOT / "manifests/core-candidate.json")
                if any(manifest["core"].get(k) != approved.get(k) for k in ("sha256", "xray", "reality", "target", "compatibility_env", "identity_env", "traffic_observer")) or manifest["pins"] != read_json(ROOT / "manifests/upstream.json"):
                    raise ValueError("Bundle dependencies differ from the approved candidate")
                if node_id == spec.entry_id:
                    core_path = "usr/local/x-ui/bin/xray-linux-amd64" if state["management"] == "panel" else "usr/local/lib/reality-proxy-kit/xray"
                    if manifest["files"].get(core_path, {}).get("sha256") != approved["sha256"]:
                        raise ValueError("Bundle core checksum differs from the approved candidate")
                if manifest["spec_revision"] != revision(spec.data) or manifest["state_revision"] != revision(state) or manifest["revision"] != record["revision"]:
                    raise ValueError("Spec or state changed since rendering; render a new candidate")
                ssh = SSH(spec.nodes[node_id]); ssh.probe()
                remote = "/var/tmp/rpk-" + secrets.token_hex(12)
                connections[node_id], remote_paths[node_id] = ssh, remote
                ssh.upload(archive, remote + ".tar.gz")
                ssh.upload(Path(__file__).with_name("remote.py"), remote + ".py")
                ssh.run(["python3", remote + ".py", "preflight", remote + ".tar.gz"])
            if spec.entry_id in receipts:
                save_backup(spec, state, args, live=True)
            elif state["management"] == "core":
                save_backup(spec, state, args)
            for node_id in [*spec.exits, spec.entry_id]:
                ssh, path = connections[node_id], remote_paths[node_id]
                results[node_id] = json.loads(ssh.run(["python3", path + ".py", "apply", path + ".tar.gz"], timeout=1800))
                receipts[node_id] = results[node_id]["revision"]
                write_json(private(args.receipts), receipts)
            after = save_backup(spec, state, args, live=True)
            return {"nodes": results, "backup": after, "network_acceptance": "pending"}
        finally:
            for node_id, remote in remote_paths.items():
                try:
                    connections[node_id].run(["rm", "-f", "--", remote + ".py", remote + ".tar.gz"])
                except Exception:
                    print("Private staging cleanup failed on " + node_id + ": " + remote + ".py and .tar.gz; remove through the verified host connection.", file=sys.stderr)
    raise ValueError("Unknown command")


def parser():
    p = argparse.ArgumentParser(prog="rpk", description="Reality Proxy Kit development candidate; no installable release yet")
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("init", "plan", "render", "apply", "export", "account", "backup", "snapshot", "refresh", "diagnose", "topology", "adopt"):
        c = commands.add_parser(name)
        c.add_argument("--spec", required=True)
        c.add_argument("--state", required=True)
        if name in ("account", "backup", "apply", "topology", "adopt"):
            c.add_argument("--key", required=True, help="Private backup key, kept separately")
            c.add_argument("--backup-dir", required=True)
        if name in ("render", "export", "snapshot", "refresh", "diagnose", "topology", "adopt"):
            c.add_argument("--output", required=True)
        if name in ("init", "export"):
            c.add_argument("--account", required=True, action="append" if name == "init" else "store")
        if name == "render":
            c.add_argument("--core", required=True)
            c.add_argument("--core-manifest", required=True)
            c.add_argument("--receipts")
            c.add_argument("--restore-db")
            c.add_argument("--adopt", action="store_true")
        if name == "apply":
            c.add_argument("--bundle", required=True)
            c.add_argument("--receipts", required=True)
        if name == "backup":
            c.add_argument("--live", action="store_true", help="Snapshot deployed entry, including native DB/site/TLS")
        if name == "account":
            c.add_argument("operation", choices=["add", "enable", "disable", "delete", "rotate", "grant"])
            c.add_argument("name")
            c.add_argument("--routes", nargs="*")
        if name == "diagnose":
            c.add_argument("--node", action="append")
        if name in ("topology", "adopt"):
            c.add_argument("--new-spec", required=True)
    r = commands.add_parser("restore")
    r.add_argument("--archive", required=True); r.add_argument("--key", required=True); r.add_argument("--output", required=True)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        result = execute(args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        # Parsing/deployment errors must not dump a credential-containing object.
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc) if isinstance(exc, ValueError) else "Operation failed; inspect private state and the redacted diagnostic report"}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
