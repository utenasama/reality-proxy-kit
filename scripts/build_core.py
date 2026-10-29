#!/usr/bin/env python3
"""Build reviewed sources without installing or contacting any VPS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PINS = {"xray": ("XTLS/Xray-core", "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74"),
        "reality": ("XTLS/REALITY", "83f621788ca88b83179810b12baa7ae518aacb83")}
OLD = "if peerPub2 == nil {\n\t\t\t\tbreak // reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before optional X25519"
NEW = "if peerPub2 == nil && !(allowLegacyX25519 && legacyX25519KeyShare(hs.clientHello.keyShares)) {\n\t\t\t\tbreak // enforce upstream profile rules unless legacy X25519 compatibility is enabled"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--go", required=True, type=Path)
    p.add_argument("--work-dir", type=Path, required=True, help="New empty directory")
    p.add_argument("--host-binary", action="store_true")
    a = p.parse_args()
    work = a.work_dir.resolve()
    if work.exists() and any(work.iterdir()):
        p.error("Use a new empty build directory")
    work.mkdir(parents=True, exist_ok=True)
    go = str(a.go.resolve())
    env = dict(os.environ, GOPATH=str(work / "gopath"), GOCACHE=str(work / "gocache"), GOTOOLCHAIN="local", CGO_ENABLED="0")
    def run(argv, cwd=work, capture=False):
        return subprocess.run(argv, cwd=cwd, env=env, check=True, text=True, capture_output=capture)
    version = run([go, "version"], capture=True).stdout.strip()
    if " go1.27.3 " not in version:
        raise SystemExit("This candidate requires Go 1.27.3")
    for name, (repo, commit) in PINS.items():
        path = work / name
        path.mkdir()
        run(["git", "init", "-q"], path)
        run(["git", "fetch", "--quiet", "--depth", "1", "https://github.com/" + repo + ".git", commit], path)
        run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], path)
        if run(["git", "rev-parse", "HEAD"], path, True).stdout.strip() != commit:
            raise SystemExit("Source revision mismatch")
    reality, xray = work / "reality", work / "xray"
    source = (reality / "tls.go").read_text()
    if source.count(OLD) != 1:
        raise SystemExit("Pinned REALITY gate does not match")
    (reality / "tls.go").write_text(source.replace(OLD, NEW))
    for name in ("legacy_x25519.go", "legacy_x25519_test.go"):
        shutil.copyfile(ROOT / "patches/reality" / name, reality / name)
    run([go, "mod", "edit", "-replace=github.com/xtls/reality=../reality"], xray)
    context_file = xray / "features/routing/session/context.go"
    context_source = context_file.read_text()
    old_identity = "return ctx.Inbound.User.Email"
    if context_source.count(old_identity) != 1:
        raise SystemExit("Pinned routing identity hook does not match")
    context_file.write_text(context_source.replace(old_identity, "return rpkRoutingUser(ctx.Inbound.User)"))
    for name in ("routing_identity.go", "routing_identity_test.go"):
        shutil.copyfile(ROOT / "patches/xray" / name, xray / "features/routing/session" / name)
    validator = xray / "proxy/vless/validator.go"
    validator_source = validator.read_text()
    edits = {"users sync.Map": "users sync.Map\n\trpkLock sync.Mutex",
             "func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {": "func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {\n\tif rpkIdentityRoutingEnabled() { return v.addRPKUser(u) }",
             "func (v *MemoryValidator) Del(e string) error {": "func (v *MemoryValidator) Del(e string) error {\n\tv.rpkLock.Lock(); defer v.rpkLock.Unlock()"}
    for old, new in edits.items():
        if validator_source.count(old) != 1:
            raise SystemExit("Pinned VLESS identity guard hook does not match")
        validator_source = validator_source.replace(old, new)
    validator.write_text(validator_source)
    for name in ("identity_guard.go", "identity_guard_test.go"):
        shutil.copyfile(ROOT / "patches/xray" / name, xray / "proxy/vless" / name)
    run([str(Path(go).with_name("gofmt")), "-w", str(xray / "proxy/vless/validator.go"), str(xray / "proxy/vless/identity_guard.go"), str(xray / "proxy/vless/identity_guard_test.go")])
    run([str(Path(go).with_name("gofmt")), "-w", str(xray / "features/routing/session"), str(reality / "legacy_x25519.go"), str(reality / "legacy_x25519_test.go")])
    tests = [["github.com/xtls/reality", "-run", "^TestLegacyX25519KeyShare$", "-count=1"],
             ["./features/routing/session", "./transport/internet/reality", "./proxy/vless/...", "./proxy/shadowsocks/...", "./proxy/shadowsocks_2022/..."],
             ["./app/router", "-run", "^(TestRoutingRule|TestSimpleRouter|TestIPOnDemand|TestIPIfNonMatchIP)$", "-count=1"]]
    for test in tests:
        run([go, "test", *test], xray)
    label = "rpk-1b1647c-legacy1-identity1"
    build = [go, "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X github.com/xtls/xray-core/core.build=" + label]
    if a.host_binary:
        run([*build, "-o", str(work / "xray-host"), "./main"], xray)
    env.update(GOOS="linux", GOARCH="amd64")
    binary = work / "xray-linux-amd64"
    run([*build, "-o", str(binary), "./main"], xray)
    modules = run([go, "list", "-m", "-json", "all"], xray, True).stdout
    (work / "modules.json").write_text(modules)
    run([go, "mod", "vendor"], xray)
    # Vendor includes modified REALITY and dependency license notices. Also include
    # its complete source (including compatibility tests), not only linked files.
    def normalize(info):
        if ".git" in Path(info.name).parts:
            return None
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        return info
    archive = work / "xray-modified-source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("xray", "reality", "modules.json"):
            tar.add(work / name, arcname=name, filter=normalize)
        for name in ("scripts/build_core.py", "patches/reality", "patches/xray", "licenses", "THIRD_PARTY_NOTICES.md", "LICENSE"):
            tar.add(ROOT / name, arcname="kit/" + name, filter=normalize)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    inputs = [Path(__file__).resolve(), *sorted((ROOT / "patches/reality").glob("*.go")), *sorted((ROOT / "patches/xray").glob("*.go"))]
    manifest = {"schema": 1, "status": "candidate", "xray": PINS["xray"][1], "reality": PINS["reality"][1],
                "go": version, "target": "linux/amd64", "build_label": label,
                "compatibility_env": "UTENASAMA_REALITY_LEGACY_X25519=1", "traffic_observer": False,
                "identity_env": "RPK_VLESS_IDENTITY_ROUTING=1",
                "inputs": {str(p.relative_to(ROOT)): sha(p) for p in inputs}, "sha256": sha(binary),
                "source_sha256": sha(archive), "tests": tests, "tests_passed": True}
    (work / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
