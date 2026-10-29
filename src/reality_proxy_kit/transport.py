"""Explicit SSH identity, pinned host keys, and no shell interpolation of data."""
import json
from pathlib import Path
import re
import shlex
import subprocess
from .model import identifier


class SSH:
    def __init__(self, node):
        self.node = node
        cfg = node.get("ssh", {})
        for key in ("key_file", "known_hosts", "machine_id"):
            if not cfg.get(key):
                raise ValueError("SSH requires key_file, known_hosts and machine_id")
        for key in ("key_file", "known_hosts"):
            if not Path(cfg[key]).is_file():
                raise ValueError("Missing SSH identity or trust file")
        if Path(cfg["key_file"]).stat().st_mode & 0o077:
            raise ValueError("SSH private key permissions are too broad")
        self.base = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                     "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=10",
                     "-o", "UserKnownHostsFile=" + cfg["known_hosts"], "-i", cfg["key_file"],
                     "-p", str(cfg.get("port", 22)), cfg.get("user", "root") + "@" + cfg.get("address", node["ipv4"])]
        self.sudo = [] if cfg.get("user", "root") == "root" else ["sudo", "-n"]

    def run(self, args, data=None, timeout=900, root=True):
        command = shlex.join((self.sudo if root else []) + list(args))
        result = subprocess.run([*self.base, command], input=data, capture_output=True, timeout=timeout)
        if result.returncode:
            # Remote output may contain a config fragment; never echo it blindly.
            raise RuntimeError("Remote operation failed (exit %d); use the redacted diagnostic command" % result.returncode)
        return result.stdout

    def probe(self):
        script = """import json,pathlib,platform,os
release=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print(json.dumps({'machine_id':pathlib.Path('/etc/machine-id').read_text().strip(),'os':release.get('ID','').strip('"'),'version':release.get('VERSION_ID','').strip('"'),'arch':platform.machine(),'root':os.geteuid()==0}))
"""
        info = json.loads(self.run(["python3", "-c", script], timeout=30))
        if info["machine_id"] != self.node["ssh"]["machine_id"]:
            raise ValueError("SSH machine identity mismatch")
        if (info["os"], info["version"], info["arch"], info["root"]) != ("ubuntu", "24.04", "x86_64", True):
            raise ValueError("Only Ubuntu 24.04 amd64 with root/noninteractive sudo is supported")
        return info

    def upload(self, local, remote):
        # stdin avoids temporary SCP filenames and shell exposure of credentials.
        script = "import pathlib,sys,os;p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);f=os.fdopen(fd,'wb');f.write(sys.stdin.buffer.read());f.close()"
        self.run(["python3", "-c", script, remote], Path(local).read_bytes())
