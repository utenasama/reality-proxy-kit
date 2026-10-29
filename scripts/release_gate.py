#!/usr/bin/env python3
"""Refuse an installable release when any mandatory acceptance evidence is missing."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "manifests/acceptance.json").read_text())
pending = [k for k, v in data["gates"].items() if v != "passed"]
if pending or not data.get("installable_release"):
    print(json.dumps({"release_allowed": False, "pending": pending}, indent=2))
    sys.exit(1)
print(json.dumps({"release_allowed": True}))
