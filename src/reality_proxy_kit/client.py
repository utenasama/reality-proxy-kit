"""Node-only exports. General VLESS URIs never carry TLS fingerprint choices."""
import base64
import json
from pathlib import Path
import uuid
from urllib.parse import quote, urlencode, urlsplit, parse_qsl, urlunsplit
import yaml
from .files import atomic_write, private_directory


def route_uuid(account_uuid, number):
    if type(number) is not int or not 1 <= number <= 65535:
        raise ValueError("Invalid route number")
    raw = bytearray(uuid.UUID(account_uuid).bytes)
    raw[6:8] = number.to_bytes(2, "big")
    return str(uuid.UUID(bytes=bytes(raw)))


def route_number(value):
    return int.from_bytes(uuid.UUID(value).bytes[6:8], "big")


def nodes(deployment, state, account):
    if not account["enabled"]:
        return []
    result = []
    for rid, route in deployment.active_routes.items():
        if rid not in account["routes"]:
            continue
        for family in ("ipv4", "ipv6"):
            address = deployment.entry.get(family)
            if not address:
                continue
            result.append({"name": route.get("label", rid) + " · " + family.upper(), "route": rid,
                           "server": address, "family": family, "port": 443,
                           "uuid": route_uuid(account["uuid"], route["number"]),
                           "sni": deployment.data["reality"]["server_names"][0],
                           "public_key": state["reality"]["public_key"], "short_id": state["reality"]["short_id"]})
    return result


def vless_uri(node):
    host = "[" + node["server"] + "]" if ":" in node["server"] else node["server"]
    params = {"type": "tcp", "encryption": "none", "security": "reality", "flow": "xtls-rprx-vision",
              "sni": node["sni"], "pbk": node["public_key"], "sid": node["short_id"]}
    return "vless://" + node["uuid"] + "@" + host + ":443?" + urlencode(params) + "#" + quote(node["name"])


def clean_uri(value):
    parsed = urlsplit(value)
    if parsed.scheme != "vless":
        raise ValueError("Unexpected subscription scheme")
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in ("fp", "fingerprint")]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), parsed.fragment))


def mihomo_node(node):
    # This is an explicit client-specific profile, not a URI default.
    return {"name": node["name"], "type": "vless", "server": node["server"], "port": 443,
            "uuid": node["uuid"], "network": "tcp", "tls": True, "flow": "xtls-rprx-vision", "udp": True,
            "servername": node["sni"], "client-fingerprint": "chrome", "ip-version": node["family"],
            "reality-opts": {"public-key": node["public_key"], "short-id": node["short_id"], "support-x25519mlkem768": True}}


def xray_profile(node, port=17808, fingerprint="chrome"):
    return {"log": {"access": "none", "loglevel": "warning"},
            "inbounds": [{"tag": "local-socks", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"tag": "proxy", "protocol": "vless",
                           "settings": {"vnext": [{"address": node["server"], "port": 443,
                                                  "users": [{"id": node["uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                           "streamSettings": {"network": "tcp", "security": "reality",
                                              "realitySettings": {"serverName": node["sni"], "password": node["public_key"],
                                                                  "shortId": node["short_id"], "fingerprint": fingerprint}}}]}


def export(deployment, state, name, directory):
    import qrcode
    import qrcode.image.svg
    account = next((a for a in state["accounts"] if a["name"] == name), None)
    if not account:
        raise ValueError("Unknown account")
    entries = nodes(deployment, state, account)
    if not entries:
        raise ValueError("Account has no authorized enabled routes")
    directory = Path(directory)
    if directory.exists():
        raise ValueError("Export to a new private directory")
    private_directory(directory)
    links = [vless_uri(n) for n in entries]
    atomic_write(directory / "nodes.txt", "\n".join(links) + "\n")
    atomic_write(directory / "mihomo-nodes.yaml", yaml.safe_dump({"proxies": [mihomo_node(n) for n in entries]}, allow_unicode=True, sort_keys=False))
    for i, (node, uri) in enumerate(zip(entries, links), 1):
        atomic_write(directory / (f"xray-{i}.json"), json.dumps(xray_profile(node), indent=2) + "\n")
        qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        atomic_write(directory / (f"node-{i}.svg"), qr.to_string())
    return {"nodes": len(entries), "directory": str(directory.resolve()), "sensitive": True}


def filter_native(body, kind, numbers, account_uuid=None):
    """Only emit independently authorized routes; reject unfamiliar layouts."""
    numbers = set(numbers)
    from .state import routing_user
    def authorized(value):
        return route_number(value) in numbers and (account_uuid is None or routing_user(value) == routing_user(account_uuid))
    if kind == "s":
        text = body.decode()
        encoded = not text.lstrip().startswith("vless://")
        if encoded:
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode()
        lines = [clean_uri(line) for line in text.splitlines() if line.strip() and authorized(urlsplit(line).username)]
        result = "\n".join(lines).encode()
        if not lines:
            raise ValueError("No authorized nodes")
        return base64.b64encode(result) if encoded else result
    if kind == "m":
        data = yaml.safe_load(body)
        if data.get("proxy-providers"):
            raise ValueError("External providers are not permitted")
        kept = [p for p in data["proxies"] if p.get("type") == "vless" and authorized(p["uuid"])]
        if not kept:
            raise ValueError("No authorized nodes")
        names = {p["name"] for p in kept}
        data["proxies"] = kept
        for group in data.get("proxy-groups", []):
            if group.get("use") or group.get("type") != "select":
                raise ValueError("Only explicit selection groups are supported")
            group["proxies"] = [name for name in group.get("proxies", []) if name in names]
            if not group["proxies"]:
                raise ValueError("Empty authorized selection group")
        return yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode()
    if kind == "x":
        data = json.loads(body)
        result = []
        for profile in (data if isinstance(data, list) else [data]):
            proxies = [o for o in profile["outbounds"] if o.get("protocol") == "vless"]
            if len(proxies) != 1:
                raise ValueError("Expected one VLESS node per Xray profile")
            settings = proxies[0]["settings"]
            users = [u for n in settings["vnext"] for u in n["users"]] if "vnext" in settings else [settings]
            if users and all(authorized(u["id"]) for u in users):
                for user in users:
                    if not user.get("encryption"):
                        user["encryption"] = "none"
                reality = proxies[0].get("streamSettings", {}).get("realitySettings", {})
                if "publicKey" in reality and "password" not in reality:
                    reality["password"] = reality.pop("publicKey")
                result.append(profile)
        if not result:
            raise ValueError("No authorized nodes")
        return json.dumps(result if isinstance(data, list) else result[0]).encode()
    raise ValueError("Unknown subscription format")
