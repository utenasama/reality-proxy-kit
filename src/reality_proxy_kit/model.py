"""Validated topology; provider names never select implementation behavior."""
import copy
import ipaddress
from pathlib import Path
import re
from .files import read_json

IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("IDs use lowercase letters, digits and hyphens")
    return value


def domain(value):
    if not isinstance(value, str) or not DOMAIN.fullmatch(value):
        raise ValueError("Expected a lowercase DNS hostname without wildcard")
    return value


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Invalid TCP/UDP port")
    return value


def target(value):
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("Remote target must be a DNS hostname:port")
    hostname, number = value.rsplit(":", 1)
    domain(hostname)
    if not number.isdecimal():
        raise ValueError("Invalid target port")
    port(int(number))
    return value


class Deployment:
    def __init__(self, data):
        self.data = copy.deepcopy(data)
        d = self.data
        if d.get("schema") != 1:
            raise ValueError("Unsupported deployment schema")
        if d.get("environment", "production") not in ("production", "test", "lab"):
            raise ValueError("Unknown environment")
        if d.get("mode") not in ("single", "chain") or d.get("management") not in ("core", "panel"):
            raise ValueError("Choose single/chain and core/panel explicitly")
        if d.get("entry_protocol", "vless-reality-vision") != "vless-reality-vision":
            raise ValueError("This release supports only VLESS REALITY Vision entry")
        if d.get("link_protocol", "ss2022") != "ss2022":
            raise ValueError("This release supports only SS2022 links; never auto-select a newer protocol")
        self.nodes = d.get("nodes", {})
        self.routes = d.get("routes", {})
        if not isinstance(self.nodes, dict) or not self.nodes:
            raise ValueError("At least one node is required")
        if d.get("entry_id") not in self.nodes:
            raise ValueError("Missing entry node")
        self.entry_id = d["entry_id"]
        for node_id, node in self.nodes.items():
            identifier(node_id)
            if node_id in ("api", "blocked", "direct", "rpk-entry", "exit-direct"):
                raise ValueError("Node ID collides with a reserved service tag")
            if node.get("role") not in ("entry", "exit"):
                raise ValueError("Unknown node role")
            if (node["role"] == "entry") != (node_id == self.entry_id):
                raise ValueError("Exactly one entry is supported")
            if ipaddress.ip_address(node["ipv4"]).version != 4:
                raise ValueError("Every node requires an IPv4 address")
            if node.get("ipv6") and ipaddress.ip_address(node["ipv6"]).version != 6:
                raise ValueError("Invalid IPv6 entry address")
            if node["role"] == "exit":
                port(node.get("proxy_port", 24443))
            if "ssh" in node:
                ssh = node["ssh"]
                port(ssh.get("port", 22))
                if not re.fullmatch(r"[a-z_][a-z0-9_-]*", ssh.get("user", "root")):
                    raise ValueError("Invalid SSH user")
                ipaddress.ip_address(ssh.get("address", node["ipv4"]))
                if not re.fullmatch(r"[a-f0-9]{32}", ssh.get("machine_id", "")):
                    raise ValueError("SSH target requires a verified machine_id")
        exits = {k for k, n in self.nodes.items() if n["role"] == "exit"}
        if d["mode"] == "single" and exits or d["mode"] == "chain" and not exits:
            raise ValueError("Topology does not match its declared mode")
        if not isinstance(self.routes, dict) or not self.routes:
            raise ValueError("Define stable routes explicitly")
        numbers = set()
        for route_id, route in self.routes.items():
            identifier(route_id)
            number = route.get("number")
            if type(number) is not int or not 1 <= number <= 65535 or number in numbers:
                raise ValueError("Route numbers must be unique integers 1..65535")
            numbers.add(number)
            if type(route.get("enabled", True)) is not bool:
                raise ValueError("Route enabled must be a boolean")
            label = route.get("label", route_id)
            if not isinstance(label, str) or not label or len(label) > 100 or any(ord(c) < 32 for c in label):
                raise ValueError("Invalid route label")
            if route.get("enabled", True):
                if d["mode"] == "single" and route.get("exit") != "direct":
                    raise ValueError("Single mode routes must exit directly")
                if d["mode"] == "chain" and route.get("exit") not in exits:
                    raise ValueError("Chain routes require a configured exit; no direct fallback")
        if not self.active_routes:
            raise ValueError("At least one enabled route is required")
        if d["mode"] == "single" and len(self.active_routes) != 1:
            raise ValueError("Single mode has one explicit direct route")
        reality = d.get("reality", {})
        if reality.get("target_mode") not in ("remote", "local"):
            raise ValueError("Choose remote or local REALITY target")
        names = reality.get("server_names", [])
        if not names or len(set(names)) != len(names):
            raise ValueError("Declare unique REALITY server_names")
        for name in names:
            domain(name)
        web = d.get("web", {})
        if type(web.get("enabled", False)) is not bool:
            raise ValueError("Web enabled must be a boolean")
        if reality["target_mode"] == "remote":
            target(reality.get("target"))
            if web.get("enabled") and web.get("domain") in names:
                raise ValueError("Remote REALITY SNI and public website SNI cannot overlap")
        elif not web.get("enabled") or web.get("domain") not in names:
            raise ValueError("Local target requires an HTTPS website matching REALITY SNI")
        if web.get("enabled"):
            domain(web.get("domain"))
            if d.get("environment", "production") != "lab" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", web.get("acme_email", "")):
                raise ValueError("Public HTTPS requires an ACME contact email")
        if d.get("subscriptions", False) and (d["management"] != "panel" or not web.get("enabled")):
            raise ValueError("Dynamic subscriptions require panel mode and HTTPS")
        if ipaddress.ip_address(d.get("dns_ipv4", "1.1.1.1")).version != 4:
            raise ValueError("DNS resolver must be an IPv4 address")

    @property
    def entry(self):
        return self.nodes[self.entry_id]

    @property
    def active_routes(self):
        return {k: v for k, v in self.routes.items() if v.get("enabled", True)}

    @property
    def exits(self):
        return {k: n for k, n in self.nodes.items() if n["role"] == "exit"}

    @property
    def front_stream(self):
        return self.data["reality"]["target_mode"] == "remote" and self.data.get("web", {}).get("enabled", False)

    @classmethod
    def read(cls, path):
        path = Path(path).resolve()
        data = read_json(path)
        for node in data.get("nodes", {}).values():
            ssh = node.get("ssh", {})
            for key in ("key_file", "known_hosts"):
                if ssh.get(key):
                    ssh[key] = str((path.parent / ssh[key]).resolve())
        if data.get("web", {}).get("static_dir"):
            data["web"]["static_dir"] = str((path.parent / data["web"]["static_dir"]).resolve())
        return cls(data)
