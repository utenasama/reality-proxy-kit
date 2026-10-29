"""Mode-aware private identities and explicit, revision-checked mutations."""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from .files import read_json, revision, write_json
from .model import identifier


def account_name(value):
    if not isinstance(value, str) or not value or len(value) > 128 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "/\\" for c in value):
        raise ValueError("Invalid account name")
    return value


def routing_user(value):
    raw = bytearray(uuid.UUID(value).bytes)
    raw[6:8] = b"\x00\x00"
    return "vless-id:" + str(uuid.UUID(bytes=bytes(raw)))


def url64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def new_account(name, routes):
    account_name(name)
    return {"id": str(uuid.uuid4()), "name": name, "uuid": str(uuid.uuid4()),
            "sub_id": secrets.token_hex(24), "enabled": True, "routes": sorted(set(routes))}


def initialize(deployment, names):
    if not names or len(set(names)) != len(names):
        raise ValueError("At least one uniquely named account is required")
    key = X25519PrivateKey.generate()
    result = {"schema": 1, "deployment_id": str(uuid.uuid4()), "generation": 0,
            "management": deployment.data["management"],
            "reality": {"private_key": url64(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                        "public_key": url64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                        "short_id": secrets.token_hex(8)},
            "accounts": [new_account(name, deployment.active_routes) for name in names],
            "links": {n: {"protocol": "ss2022", "key": base64.b64encode(secrets.token_bytes(32)).decode()} for n in deployment.exits},
            "route_registry": {r: {"number": v["number"], "exit": v["exit"]} for r, v in deployment.routes.items()},
            "retired_accounts": [],
            "panel": {"username": "admin", "password": secrets.token_urlsafe(32)}}
    return validate(result, deployment)


def validate(state, deployment):
    if state.get("schema") != 1 or state.get("management") not in ("core", "panel"):
        raise ValueError("Unsupported private state")
    uuid.UUID(state["deployment_id"])
    if state["management"] != deployment.data["management"]:
        raise ValueError("Management changes require the explicit adopt operation")
    r = state["reality"]
    private = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(r["private_key"] + "="))
    if url64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)) != r["public_key"]:
        raise ValueError("REALITY key pair does not match")
    if len(bytes.fromhex(r["short_id"])) != 8:
        raise ValueError("Expected an 8-byte REALITY short ID")
    registry = state.get("route_registry", {})
    used = {x["number"]: k for k, x in registry.items()}
    for route_id, route in deployment.routes.items():
        identity = {"number": route["number"], "exit": route["exit"]}
        if route_id not in registry or registry[route_id] != identity:
            raise ValueError("Topology identities changed; use the explicit topology reconciliation operation")
        if used.get(route["number"]) != route_id:
            raise ValueError("A retired route number cannot be reused")
    for node_id in deployment.exits:
        link = state["links"].get(node_id, {})
        if link.get("protocol") != "ss2022" or len(base64.b64decode(link.get("key", ""), validate=True)) != 32:
            raise ValueError("Invalid or missing independent SS2022 link key")
    names, ids, uuids, tokens = set(), set(), set(), set()
    for a in state["accounts"]:
        account_name(a["name"])
        uuid.UUID(a["id"]); uuid.UUID(a["uuid"])
        if type(a["enabled"]) is not bool or not set(a["routes"]) <= registry.keys():
            raise ValueError("Invalid account authorization")
        for key, seen in (("name", names), ("id", ids), ("uuid", uuids), ("sub_id", tokens)):
            normalized = routing_user(a[key]) if key == "uuid" else str(uuid.UUID(a[key])) if key == "id" else a[key].lower() if key == "name" else a[key]
            if normalized in seen:
                raise ValueError("Duplicate account identity")
            seen.add(normalized)
    return state


def mutate(state, deployment, action, name, routes=None):
    """Pure function. Live panel instances are changed through the panel backend."""
    validate(state, deployment)
    result = copy.deepcopy(state)
    account = next((a for a in result["accounts"] if a["name"] == name), None)
    if routes is not None and not set(routes) <= deployment.active_routes.keys():
        raise ValueError("Grant only enabled routes")
    if action == "add":
        if account:
            raise ValueError("Account already exists")
        result["accounts"].append(new_account(name, routes if routes is not None else deployment.active_routes))
    else:
        if not account:
            raise ValueError("Account not found")
        if action in ("enable", "disable"):
            account["enabled"] = action == "enable"
        elif action == "grant":
            account["routes"] = sorted(set(routes or []))
        elif action == "rotate":
            account["uuid"] = str(uuid.uuid4())
            account["sub_id"] = secrets.token_hex(24)
        elif action == "delete":
            result["accounts"].remove(account)
            result["retired_accounts"].append(account["id"])
        else:
            raise ValueError("Unsupported account operation")
    result["generation"] += 1
    return validate(result, deployment)


def reconcile(state, deployment):
    """Append new identities, retain tombstones and existing credentials."""
    result = copy.deepcopy(state)
    registry = result["route_registry"]
    numbers = {r["number"] for r in registry.values()}
    for rid, route in deployment.routes.items():
        ident = {"number": route["number"], "exit": route["exit"]}
        if rid in registry and registry[rid] != ident:
            raise ValueError("Existing route identity cannot be redefined")
        if rid not in registry:
            if route["number"] in numbers:
                raise ValueError("Route number was already used")
            registry[rid] = ident
            numbers.add(route["number"])
    for node in deployment.exits:
        if node not in result["links"]:
            result["links"][node] = {"protocol": "ss2022", "key": base64.b64encode(secrets.token_bytes(32)).decode()}
    result["generation"] += 1
    return validate(result, deployment)


def locked_update(path, expected, operation):
    path = Path(path)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = read_json(path)
            if revision(current) != expected:
                raise ValueError("State changed since it was read; refresh before retrying")
            updated = operation(current)
            write_json(path, updated)
            return updated
    except Exception:
        raise
