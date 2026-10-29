import base64
import copy
import io
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs
from reality_proxy_kit import backup, client, compiler, config, state
from reality_proxy_kit.files import digest, read_json, revision, write_json
from reality_proxy_kit.model import Deployment
from reality_proxy_kit.remote import unpack

ROOT = Path(__file__).resolve().parents[1]


def deployment(mode="single", management="core", target="remote", web=False):
    d = read_json(ROOT / "examples" / (mode + ".json"))
    d.update(environment="lab", management=management)
    if target == "local" or web:
        d["web"] = {"enabled": True, "domain": "site.example.org"}
    if target == "local":
        d["reality"] = {"target_mode": "local", "server_names": ["site.example.org"]}
    return Deployment(d)


class Models(unittest.TestCase):
    def test_eight_combinations_and_private_exports(self):
        for mode in ("single", "chain"):
            for management in ("core", "panel"):
                for target in ("remote", "local"):
                    with self.subTest(mode=mode, management=management, target=target):
                        d = deployment(mode, management, target)
                        s = state.initialize(d, ["alice", "bob"])
                        state.validate(s, d)
                        server = config.entry_config(d, s)
                        self.assertEqual(server["outbounds"][0]["protocol"], "blackhole")
                        self.assertEqual(server["routing"]["rules"][-1]["outboundTag"], "blocked")
                        self.assertNotIn("freedom", [o["protocol"] for o in server["outbounds"]] if mode == "chain" else [])
                        for n in client.nodes(d, s, s["accounts"][0]):
                            self.assertNotIn("fp", parse_qs(urlsplit(client.vless_uri(n)).query))
                        self.assertEqual(config.allowed_routes(d, s["accounts"], server, s["accounts"][0]), sorted(d.active_routes))

    def test_disabled_account_has_no_export_but_grants_survive(self):
        d = deployment("chain", "panel"); s = state.initialize(d, ["alice"])
        disabled = state.mutate(s, d, "disable", "alice")
        self.assertEqual(client.nodes(d, disabled, disabled["accounts"][0]), [])
        restored = state.mutate(disabled, d, "enable", "alice")
        self.assertEqual(restored["accounts"][0]["routes"], s["accounts"][0]["routes"])

    def test_acl_has_no_implicit_all_routes(self):
        d = deployment("chain"); s = state.initialize(d, ["alice", "bob"])
        s = state.mutate(s, d, "grant", "alice", ["route-a"])
        self.assertEqual({n["route"] for n in client.nodes(d, s, s["accounts"][0])}, {"route-a"})
        rules = config.entry_config(d, s)
        self.assertEqual(config.allowed_routes(d, s["accounts"], rules, s["accounts"][0]), ["route-a"])
        rules["routing"]["rules"].insert(0, {"type": "field", "network": "tcp,udp", "outboundTag": "exit-b"})
        with self.assertRaises(ValueError):
            config.allowed_routes(d, s["accounts"], rules, s["accounts"][0])

    def test_missing_guard_rejects(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        template = config.panel_template(d, s)
        template["routing"]["rules"] = [r for r in template["routing"]["rules"] if r.get("ruleTag") != config.GUARD]
        with self.assertRaises(ValueError):
            config.allowed_routes(d, s["accounts"], template, s["accounts"][0])

    def test_route_identity_cannot_be_repurposed(self):
        d = deployment("chain"); s = state.initialize(d, ["alice"])
        changed = copy.deepcopy(d.data); changed["routes"]["route-a"]["exit"] = "exit-b"
        with self.assertRaises(ValueError):
            state.reconcile(s, Deployment(changed))

    def test_retired_number_cannot_be_reused(self):
        d = deployment("chain"); s = state.initialize(d, ["alice"])
        changed = copy.deepcopy(d.data)
        changed["routes"]["replacement"] = changed["routes"].pop("route-a")
        with self.assertRaises(ValueError):
            state.reconcile(s, Deployment(changed))

    def test_rotation_keeps_stable_account_and_routes(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        rotated = state.mutate(s, d, "rotate", "alice")
        old, new = s["accounts"][0], rotated["accounts"][0]
        self.assertEqual((old["id"], old["routes"]), (new["id"], new["routes"]))
        self.assertNotEqual(old["uuid"], new["uuid"])
        self.assertNotEqual(old["sub_id"], new["sub_id"])

    def test_wrong_management_requires_adoption(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        with self.assertRaises(ValueError):
            state.validate(s, deployment(management="panel"))

    def test_single_to_chain_retains_old_meaning_and_credentials(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        data = deployment("chain").data
        data["routes"]["direct-v1"] = dict(d.routes["direct-v1"], enabled=False)
        new = state.reconcile(s, Deployment(data))
        self.assertEqual(new["reality"], s["reality"])
        self.assertEqual(new["accounts"], s["accounts"])
        self.assertEqual(client.nodes(Deployment(data), new, new["accounts"][0]), [])
        self.assertEqual(new["route_registry"]["direct-v1"]["exit"], "direct")

    def test_per_exit_keys_independent(self):
        d = deployment("chain"); s = state.initialize(d, ["alice"])
        self.assertNotEqual(s["links"]["exit-a"]["key"], s["links"]["exit-b"]["key"])

    def test_native_same_name_recreation_gets_no_old_grants(self):
        d = deployment("chain", "panel"); s = state.initialize(d, ["alice"])
        template = config.entry_config(d, s)
        replacement = state.new_account("alice", [])
        replacement["id"] = s["accounts"][0]["id"]
        self.assertEqual(config.allowed_routes(d, s["accounts"], template, replacement), [])

    def test_vless_route_byte_collision_rejects(self):
        d = deployment(); s = state.initialize(d, ["alice", "bob"])
        s["accounts"][1]["uuid"] = client.route_uuid(s["accounts"][0]["uuid"], 99)
        with self.assertRaises(ValueError): state.validate(s, d)

    def test_native_email_and_unicode_names_supported(self):
        d = deployment(); s = state.initialize(d, ["alice@example.com", "user_1", "测试"])
        state.mutate(s, d, "disable", "测试")

    def test_native_invalid_name_and_case_collision_reject(self):
        d = deployment()
        for name in ("bad/name", "bad\\name", "bad\x7f"):
            with self.assertRaises(ValueError): state.initialize(d, [name])
        with self.assertRaises(ValueError): state.initialize(d, ["alice", "ALICE"])

    def test_reserved_exit_tag_rejects(self):
        d = deployment("chain").data
        d["nodes"]["blocked"] = d["nodes"].pop("exit-a")
        d["routes"]["route-a"]["exit"] = "blocked"
        with self.assertRaises(ValueError): Deployment(d)

    def test_offline_plan_identifies_missing_deployment_inputs(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        p = compiler.plan(d, s)
        self.assertFalse(p["deployable"])
        self.assertIn("entry:ssh.machine_id", p["missing_inputs"])

    def test_sni_collision_and_unsupported_protocols_reject(self):
        d = deployment(web=True).data
        d["web"]["domain"] = d["reality"]["server_names"][0]
        with self.assertRaises(ValueError): Deployment(d)
        d = deployment().data; d["link_protocol"] = "latest"
        with self.assertRaises(ValueError): Deployment(d)

    def test_revision_compare_and_swap(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"; write_json(path, s)
            state.locked_update(path, revision(s), lambda current: state.mutate(current, d, "disable", "alice"))
            with self.assertRaises(ValueError):
                state.locked_update(path, revision(s), lambda current: state.mutate(current, d, "rotate", "alice"))


class Exports(unittest.TestCase):
    def setUp(self):
        self.d = deployment("chain"); self.s = state.initialize(self.d, ["alice"])
        self.nodes = client.nodes(self.d, self.s, self.s["accounts"][0])

    def test_native_uri_filters_and_removes_encoded_fingerprint(self):
        lines = [client.vless_uri(n).replace("?", "?%66%70=chrome&Fingerprint=safari&") for n in self.nodes]
        body = base64.b64encode("\n".join(lines).encode())
        result = base64.b64decode(client.filter_native(body, "s", [101])).decode().splitlines()
        self.assertEqual(len(result), 1)
        self.assertEqual(client.route_number(urlsplit(result[0]).username), 101)
        self.assertFalse({k.lower() for k in parse_qs(urlsplit(result[0]).query)} & {"fp", "fingerprint"})

    def test_native_mihomo_preserves_specific_fingerprint(self):
        import yaml
        body = yaml.safe_dump({"proxies": [client.mihomo_node(n) for n in self.nodes], "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [n["name"] for n in self.nodes]}]}).encode()
        result = yaml.safe_load(client.filter_native(body, "m", [101]))
        self.assertEqual(len(result["proxies"]), 1)
        self.assertEqual(result["proxies"][0]["client-fingerprint"], "chrome")
        self.assertEqual(len(result["proxy-groups"][0]["proxies"]), 1)

    def test_native_xray_filters_without_global_fingerprint_removal(self):
        profiles = [client.xray_profile(n) for n in self.nodes]
        result = json.loads(client.filter_native(json.dumps(profiles).encode(), "x", [102]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"], "chrome")

    def test_exports_are_private_and_node_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "export"
            result = client.export(self.d, self.s, "alice", output)
            self.assertEqual(result["nodes"], 2)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o077 == 0 for p in output.iterdir()))
            self.assertNotIn("proxy-groups", (output / "mihomo-nodes.yaml").read_text())
            with self.assertRaises(ValueError): client.export(self.d, self.s, "alice", output)


class Recovery(unittest.TestCase):
    def test_native_snapshot_read_and_backup_preserve_same_authority(self):
        from reality_proxy_kit import panel
        d = deployment("chain", "panel"); s = state.initialize(d, ["alice"])
        s = state.mutate(s, d, "grant", "alice", ["route-a"])
        a = s["accounts"][0]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "panel.db"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE settings(key TEXT,value TEXT)")
                db.execute("INSERT INTO settings VALUES(?,?)", ("xrayTemplateConfig", json.dumps(config.panel_template(d, s))))
                db.execute("CREATE TABLE clients(id INTEGER PRIMARY KEY, email TEXT, uuid TEXT, sub_id TEXT, enable INT, comment TEXT)")
                db.execute("INSERT INTO clients VALUES(?,?,?,?,?,?)", (1, a["name"], a["uuid"], a["sub_id"], 1, "rpk:id:" + a["id"]))
            full, image, token = panel.snapshot(d, s, path)
            readonly, empty, token2 = panel.snapshot(d, s, path, include_database=False)
            self.assertEqual(full, readonly)
            self.assertEqual(token, token2)
            self.assertEqual(full["accounts"][0]["routes"], ["route-a"])
            self.assertTrue(image.startswith(b"SQLite format 3"))
            self.assertEqual(empty, b"")

    def test_round_trip_preserves_all_identities(self):
        for management in ("core", "panel"):
            d = deployment("chain", management); s = state.initialize(d, ["alice"])
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); archive = root / "backups/a.rpk"; key = root / "key/recovery.key"
                extra = {"panel.db": b"fixture"} if management == "panel" else {}
                backup.create(d.data, s, archive, key, extra)
                backup.restore(archive, key, root / "restored")
                self.assertEqual(read_json(root / "restored/state.json"), s)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(s["reality"]["private_key"].encode(), archive.read_bytes())
                with self.assertRaises(ValueError): backup.restore(archive, key, root / "restored")

    def test_corruption_truncation_and_wrong_key_reject(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / "backups/a.rpk"; key = root / "keys/a.key"
            backup.create(d.data, s, archive, key)
            original = archive.read_bytes()
            for data in (original[:-1], original[:20], original[:-1] + bytes([original[-1] ^ 1])):
                archive.write_bytes(data)
                with self.assertRaises(ValueError): backup.read(archive, key)
            archive.write_bytes(original); key.write_bytes(os.urandom(32))
            with self.assertRaises(ValueError): backup.read(archive, key)

    def test_missing_panel_db_and_traversal_reject(self):
        d = deployment(management="panel"); s = state.initialize(d, ["alice"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError): backup.create(d.data, s, root / "b/a", root / "k/key")
        for name in ("../state.json", "/etc/passwd", "a/../b", "a\\b"):
            with self.assertRaises(ValueError): backup.safe_name(name)

    def test_key_must_be_separate(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError): backup.create(d.data, s, root / "backup", root / "key")


class Bundle(unittest.TestCase):
    def test_binary_tamper_and_production_reject_before_render(self):
        d = deployment(); s = state.initialize(d, ["alice"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / "core").write_bytes(b"not a core")
            with self.assertRaises(ValueError):
                compiler.compile_bundle(d, s, path / "out", path / "core", ROOT / "manifests/core-candidate.json")
            self.assertFalse((path / "out").exists())

    def test_archive_symlinks_and_traversal_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.tar"
            for name in ("../bad", "/etc/passwd"):
                with tarfile.open(archive, "w") as tar:
                    info = tarfile.TarInfo(name); info.size = 1
                    tar.addfile(info, io.BytesIO(b"x"))
                with self.assertRaises(ValueError): unpack(archive)

    def test_firewall_is_source_restricted_and_marked(self):
        d = deployment("chain")
        text = compiler.firewall(d, "exit-a")
        self.assertIn("ip saddr 203.0.113.10 tcp dport 24443 accept", text)
        self.assertIn("meta mark 48211", text)
        self.assertNotIn("flush ruleset", text)


class CoreSyntax(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("RPK_XRAY"), "Set RPK_XRAY to the reviewed host binary")
    def test_all_eight_generated_configs_with_real_core(self):
        for mode in ("single", "chain"):
            for management in ("core", "panel"):
                for target in ("remote", "local"):
                    d = deployment(mode, management, target)
                    s = state.initialize(d, ["alice"])
                    with tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp) / "config.json"; write_json(path, config.entry_config(d, s))
                        r = subprocess.run([os.environ["RPK_XRAY"], "run", "-test", "-c", str(path)], capture_output=True)
                        self.assertEqual(r.returncode, 0, r.stderr.decode())


if __name__ == "__main__":
    unittest.main()
