"""3x-ui v3.11.0 native API adapter. Never writes a running SQLite database."""
import copy
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from .config import INBOUND, allowed_routes, inbound, panel_template
from .files import revision
from .state import routing_user


class API:
    def __init__(self, credentials, hostname="localhost"):
        self.base = "http://127.0.0.1:54321/admin/"
        self.hostname, self.csrf = hostname, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = self.call("csrf-token")
        self.call("login", credentials)
        self.csrf = self.call("csrf-token")

    def call(self, path, data=None, json_body=False):
        headers = {"Host": self.hostname, "Origin": "http://" + self.hostname,
                   "Referer": "http://" + self.hostname + "/admin/", "X-Requested-With": "XMLHttpRequest"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if json_body:
            headers["Content-Type"] = "application/json"
        body = None if data is None else (json.dumps(data).encode() if json_body else urllib.parse.urlencode(data).encode())
        with self.opener.open(urllib.request.Request(self.base + path, body, headers), timeout=20) as response:
            result = json.load(response)
        if result.get("success") is not True:
            raise RuntimeError("Native panel API rejected the operation")
        return result.get("obj")


def client_record(account):
    return {"id": account["uuid"], "email": account["name"], "enable": account["enabled"],
            "flow": "xtls-rprx-vision", "subId": account["sub_id"], "comment": "rpk:id:" + account["id"], "totalGB": 0, "expiryTime": 0}


def client_update_payload(record, account):
    # GET returns ClientRecord; UPDATE consumes Client. Mirror the pinned
    # upstream ToClient conversion for fields with different JSON shapes.
    result = copy.deepcopy(record)
    result.pop("uuid", None)
    allowed = result.get("allowedIPs", "")
    if isinstance(allowed, str):
        result["allowedIPs"] = [v.strip() for v in allowed.split(",") if v.strip()]
    reverse = result.get("reverse")
    if isinstance(reverse, str):
        result["reverse"] = json.loads(reverse) if reverse else None
    for key in ("createdAt", "updatedAt"):
        if key in result:
            result[{"createdAt": "created_at", "updatedAt": "updated_at"}[key]] = result.pop(key)
    changed = client_record(account)
    # Native quota, expiry and other optional metadata remain authoritative.
    changed.pop("totalGB"); changed.pop("expiryTime")
    result.update(changed)
    return result


def settings(deployment, state):
    domain = deployment.data.get("web", {}).get("domain", "localhost")
    return {"webListen": "127.0.0.1", "webPort": "54321", "webBasePath": "/admin/",
            "webCertFile": "", "webKeyFile": "", "subEnable": "true", "subListen": "127.0.0.1",
            "subPort": "2096", "subPath": "/s/", "subJsonEnable": "true", "subJsonPath": "/x/",
            "subClashEnable": "true", "subClashPath": "/m/", "subURI": "https://" + domain + "/s/",
            "subJsonURI": "https://" + domain + "/x/", "subClashURI": "https://" + domain + "/m/",
            "remarkTemplate": "{{HOST}}", "subClashEnableRouting": "true",
            "subClashRules": "proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: []\nrules:\n  - MATCH,PROXY\n",
            "xrayTemplateConfig": json.dumps(panel_template(deployment, state))}


def prepare(deployment, state, db_path="/etc/x-ui/x-ui.db"):
    if Path(db_path).exists():
        raise ValueError("Panel preparation requires an empty database path")
    mask = os.umask(0o077)
    try:
        result = subprocess.run(["/usr/local/x-ui/x-ui", "setting", "-username", state["panel"]["username"],
                                 "-password", state["panel"]["password"], "-port", "54321", "-listenIP", "127.0.0.1",
                                 "-webBasePath", "/admin/"], capture_output=True)
    finally:
        os.umask(mask)
    if result.returncode:
        raise RuntimeError("Unable to initialize native panel")
    # This function is called before starting the panel, only on an empty host.
    with sqlite3.connect(db_path) as db:
        for k, v in settings(deployment, state).items():
            if not db.execute("UPDATE settings SET value=? WHERE key=?", (v, k)).rowcount:
                db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k, v))


def publish(deployment, state, api=None, initial=False):
    api = api or API(state["panel"])
    inbounds = api.call("panel/api/inbounds/list")
    proxy = next((i for i in inbounds if i["tag"] == INBOUND), None)
    if proxy is None:
        if not initial or inbounds:
            raise ValueError("Cannot take over an unrelated native panel")
        raw = inbound(deployment, state)
        raw["settings"]["clients"] = [client_record(a) for a in state["accounts"]]
        raw["settings"]["encryption"] = "none"
        raw["streamSettings"]["realitySettings"]["settings"] = {
            "publicKey": state["reality"]["public_key"], "fingerprint": "",
            "serverName": deployment.data["reality"]["server_names"][0], "spiderX": "/"}
        record = {"enable": True, "remark": "Reality Proxy Kit", **raw}
        for k in ("settings", "streamSettings", "sniffing"):
            record[k] = json.dumps(record[k])
        api.call("panel/api/inbounds/add", record)
        proxy = next(i for i in api.call("panel/api/inbounds/list") if i["tag"] == INBOUND)
    else:
        # Preserve native client records (including native optional metadata).
        raw = inbound(deployment, state)
        raw["streamSettings"]["realitySettings"]["settings"] = {
            "publicKey": state["reality"]["public_key"], "fingerprint": "",
            "serverName": deployment.data["reality"]["server_names"][0], "spiderX": "/"}
        updated = dict(proxy, listen=raw["listen"], port=raw["port"],
                       streamSettings=json.dumps(raw["streamSettings"]), sniffing=json.dumps(raw["sniffing"]))
        api.call("panel/api/inbounds/update/" + str(proxy["id"]), updated)
    hosts = api.call("panel/api/hosts/list") or []
    desired = []
    for rid, route in deployment.active_routes.items():
        for family in ("ipv4", "ipv6"):
            address = deployment.entry.get(family)
            if not address:
                continue
            desired.append({"inboundIds": [proxy["id"]], "remark": route.get("label", rid) + " · " + family.upper(),
                            "hosts": [("[" + address + "]" if family == "ipv6" else address) + ":443"],
                            "port": 443, "security": "same", "sni": deployment.data["reality"]["server_names"][0],
                            "vlessRoute": str(route["number"]), "mihomoX25519": True,
                            "mihomoIpVersion": family, "isDisabled": False, "sortOrder": route["number"]})
    wanted = {(r["vlessRoute"], r["mihomoIpVersion"]) for r in desired}
    for old in hosts:
        if proxy["id"] in old.get("inboundIds", []) and (old.get("vlessRoute"), old.get("mihomoIpVersion")) not in wanted:
            api.call("panel/api/hosts/update/" + str(old["groupId"]), dict(old, isDisabled=True), True)
    for row in desired:
        old = next((h for h in hosts if proxy["id"] in h.get("inboundIds", []) and
                    (h.get("vlessRoute"), h.get("mihomoIpVersion")) == (row["vlessRoute"], row["mihomoIpVersion"])), None)
        if old:
            api.call("panel/api/hosts/update/" + str(old["groupId"]), dict(old, **row), True)
        else:
            api.call("panel/api/hosts/add", row, True)
    current = api.call("panel/api/setting/all", {})
    desired_settings = settings(deployment, state)
    desired_settings["subClashRules"] = json.dumps({"proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [r["remark"] for r in desired]}], "rules": ["MATCH,PROXY"]})
    for key, value in desired_settings.items():
        if key == "xrayTemplateConfig":
            continue
        old = current.get(key)
        current[key] = (value == "true") if isinstance(old, bool) else int(value) if isinstance(old, int) else value
    api.call("panel/api/setting/update", current, True)
    update_template(api, panel_template(deployment, state))


def update_template(api, template):
    x = api.call("panel/api/xray/", {})
    if isinstance(x, str):
        x = json.loads(x)
    api.call("panel/api/xray/update", {"xraySetting": json.dumps(template),
                                      "outboundTestUrl": x.get("outboundTestUrl", "https://www.gstatic.com/generate_204")})


def snapshot(deployment, seed, db_path="/etc/x-ui/x-ui.db", include_database=True):
    """Use SQLite backup for one consistent DB image; traffic counters aren't CAS inputs."""
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(contextlib.closing(sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True)))
        if include_database:
            db = stack.enter_context(contextlib.closing(sqlite3.connect(":memory:")))
            source.backup(db)
        else:
            db = source
            db.execute("BEGIN")
        db.row_factory = sqlite3.Row
        template = json.loads(db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0])
        native = [dict(r) for r in db.execute("SELECT id,email,uuid,sub_id,enable,comment FROM clients ORDER BY id")]
        image = b""
        if include_database:
            with tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "snapshot.db"
                with sqlite3.connect(target) as dest:
                    db.backup(dest)
                image = target.read_bytes()
    result = copy.deepcopy(seed)
    mapping = {}
    for rule in template.get("routing", {}).get("rules", []):
        tag = rule.get("ruleTag", "")
        if tag.startswith("rpk:account:") and len(rule.get("user", [])) == 1 and rule.get("outboundTag") == "blocked":
            mapping[rule["user"][0]] = str(uuid.UUID(tag[len("rpk:account:"):]))
    result["accounts"] = []
    for row in native:
        stable = str(uuid.UUID(row["comment"][7:])) if (row.get("comment") or "").startswith("rpk:id:") else mapping.get(routing_user(row["uuid"]), str(uuid.uuid5(uuid.UUID(seed["deployment_id"]), "panel:" + str(row["id"]))))
        account = {"id": stable,
                   "name": row["email"], "uuid": row["uuid"], "sub_id": row["sub_id"], "enabled": bool(row["enable"]), "routes": []}
        account["routes"] = allowed_routes(deployment, native, template, dict(account, enabled=True))
        result["accounts"].append(account)
    # Include native config changes in the optimistic concurrency token.
    token = revision({"accounts": result["accounts"], "template": template})
    return result, image, token


def change_account(deployment, seed, action, name, routes, expected):
    from .state import mutate
    live, _, token = snapshot(deployment, seed)
    if token != expected:
        raise ValueError("Panel state changed; refresh the snapshot before retrying")
    after = mutate(live, deployment, action, name, routes)
    api = API(seed["panel"])
    current = api.call("panel/api/xray/", {})
    current = json.loads(current) if isinstance(current, str) else current
    current_template = current["xraySetting"]
    current_template = json.loads(current_template) if isinstance(current_template, str) else current_template
    baseline = panel_template(deployment, live)
    # Native account/ACL data is authoritative. Unsupported structural edits are
    # drift, and must not be silently replaced using a stale recovery seed.
    strip_acl = lambda t: {**t, "routing": {**t.get("routing", {}), "rules": [r for r in t.get("routing", {}).get("rules", []) if not r.get("ruleTag", "").startswith(("rpk:acl:", "rpk:account:"))]}}
    if strip_acl(current_template) != strip_acl(baseline):
        raise ValueError("Native template has structural changes; reconcile them before account maintenance")
    target = next((a for a in after["accounts"] if a["name"] == name), None)
    proxy = next(i for i in api.call("panel/api/inbounds/list") if i["tag"] == INBOUND)
    # Revoke first. If a later API call fails, the affected identity remains denied.
    denied = copy.deepcopy(live)
    for account in denied["accounts"]:
        if account["name"] == name:
            account["routes"] = []
    update_template(api, panel_template(deployment, denied))
    if action == "add":
        api.call("panel/api/clients/add", {"client": client_record(target), "inboundIds": [proxy["id"]]}, True)
    elif action == "delete":
        api.call("panel/api/clients/del/" + urllib.parse.quote(name, safe=""), {}, True)
    elif action != "grant":
        old = api.call("panel/api/clients/get/" + urllib.parse.quote(name, safe=""))["client"]
        api.call("panel/api/clients/update/" + urllib.parse.quote(name, safe=""), client_update_payload(old, target), True)
    update_template(api, panel_template(deployment, after))
    return after
