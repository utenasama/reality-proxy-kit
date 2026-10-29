"""Pure configuration builders for both topologies and all target combinations."""
import copy
import json
from . import state as identities

INBOUND = "rpk-entry"
ACL = "rpk:acl:"
GUARD = "rpk:guard"
PRIVATE_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
              "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
              "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"]


def inbound(deployment, state):
    identities.validate(state, deployment)
    data, reality = deployment.data, deployment.data["reality"]
    local = reality["target_mode"] == "local"
    stream = {"network": "tcp", "security": "reality", "realitySettings": {
        "show": False, "target": "127.0.0.1:8444" if local else reality["target"],
        "xver": 1 if local else 0, "serverNames": reality["server_names"],
        "privateKey": state["reality"]["private_key"], "shortIds": [state["reality"]["short_id"]]}}
    if deployment.front_stream:
        stream["sockopt"] = {"acceptProxyProtocol": True}
    return {"tag": INBOUND, "listen": "127.0.0.1" if deployment.front_stream else ("::" if deployment.entry.get("ipv6") else "0.0.0.0"),
            "port": 9443 if deployment.front_stream else 443, "protocol": "vless",
            "settings": {"clients": [{"id": a["uuid"], "email": a["name"], "flow": "xtls-rprx-vision"}
                                     for a in state["accounts"] if a["enabled"]], "decryption": "none"},
            "streamSettings": stream,
            "sniffing": {"enabled": False}}


def routing(deployment, state):
    outbounds = [{"tag": "blocked", "protocol": "blackhole", "settings": {}}]
    rules = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
             {"type": "field", "ip": PRIVATE_V4 + ["::/0"], "outboundTag": "blocked"}]
    if deployment.data["mode"] == "single":
        rules.insert(1, {"type": "field", "inboundTag": ["rpk-dns"], "ip": [deployment.data.get("dns_ipv4", "1.1.1.1")],
                         "port": "53", "network": "udp", "outboundTag": "direct"})
        outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"},
                          "streamSettings": {"sockopt": {"mark": 48211}}})
    else:
        for node_id, node in deployment.exits.items():
            outbounds.append({"tag": node_id, "protocol": "shadowsocks", "settings": {"servers": [
                {"address": node["ipv4"], "port": node.get("proxy_port", 24443),
                 "method": "2022-blake3-aes-256-gcm", "password": state["links"][node_id]["key"]}]}})
    for account in state["accounts"]:
        for route_id in sorted(set(account["routes"]) & deployment.active_routes.keys()):
            route = deployment.routes[route_id]
            rules.append({"type": "field", "inboundTag": [INBOUND], "user": [identities.routing_user(account["uuid"])],
                          "vlessRoute": str(route["number"]), "outboundTag": route["exit"],
                          "ruleTag": ACL + account["id"] + ":" + route_id})
    # Account mapping is authoritative in the panel's routing template even for
    # accounts without any grants. This deny cannot broaden permissions.
    for account in state["accounts"]:
        rules.append({"type": "field", "inboundTag": [INBOUND], "user": [identities.routing_user(account["uuid"])],
                      "outboundTag": "blocked", "ruleTag": "rpk:account:" + account["id"]})
    rules += [{"type": "field", "inboundTag": [INBOUND], "outboundTag": "blocked", "ruleTag": GUARD},
              {"type": "field", "network": "tcp,udp", "outboundTag": "blocked"}]
    return outbounds, {"domainStrategy": "IPOnDemand" if deployment.data["mode"] == "single" else "AsIs", "rules": rules}


def entry_config(deployment, state):
    proxy = inbound(deployment, state)
    outbounds, rules = routing(deployment, state)
    return {"log": {"access": "none", "loglevel": "warning"},
            "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
            "stats": {}, "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
            "dns": {"tag": "rpk-dns", "servers": [deployment.data.get("dns_ipv4", "1.1.1.1")], "queryStrategy": "UseIPv4"},
            "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
                          "settings": {"address": "127.0.0.1"}}, proxy],
            "outbounds": outbounds, "routing": rules}


def panel_template(deployment, state):
    result = entry_config(deployment, state)
    result["inbounds"] = [i for i in result["inbounds"] if i["tag"] != INBOUND]
    return result


def exit_config(deployment, state, node_id):
    node = deployment.exits[node_id]
    return {"log": {"level": "warn", "timestamp": True},
            "dns": {"servers": [{"type": "udp", "tag": "exit-dns", "server": deployment.data.get("dns_ipv4", "1.1.1.1")}],
                    "strategy": "ipv4_only"},
            "inbounds": [{"type": "shadowsocks", "tag": "from-entry", "listen": "0.0.0.0",
                          "listen_port": node.get("proxy_port", 24443), "method": "2022-blake3-aes-256-gcm",
                          "password": state["links"][node_id]["key"]}],
            "outbounds": [{"type": "direct", "tag": "exit-direct", "routing_mark": 48211}],
            "route": {"default_domain_resolver": {"server": "exit-dns", "strategy": "ipv4_only"},
                      "rules": [{"action": "resolve", "server": "exit-dns", "strategy": "ipv4_only"},
                                {"ip_cidr": PRIVATE_V4 + ["::/0"], "action": "reject"},
                                {"ip_is_private": True, "action": "reject"}], "final": "exit-direct"}}


def allowed_routes(deployment, accounts, template, account):
    """Fail closed when a native template could bypass the published ACL."""
    rules = template.get("routing", {}).get("rules", [])
    outbounds = template.get("outbounds", [])
    tags = [o.get("tag") for o in outbounds]
    if len(tags) != len(set(tags)) or next((o for o in outbounds if o.get("tag") == "blocked"), None) != {"tag": "blocked", "protocol": "blackhole", "settings": {}}:
        raise ValueError("Authorization sink was changed")
    required_private = {"type": "field", "ip": PRIVATE_V4 + ["::/0"], "outboundTag": "blocked"}
    if required_private not in rules or template.get("routing", {}).get("domainStrategy") != ("IPOnDemand" if deployment.data["mode"] == "single" else "AsIs"):
        raise ValueError("Destination boundary was changed")
    if template.get("routing", {}).get("script"):
        raise ValueError("Unexpected script routing")
    guards = [i for i, r in enumerate(rules) if r.get("ruleTag") == GUARD]
    if len(guards) != 1:
        raise ValueError("Missing authorization guard")
    guard = guards[0]
    if rules[guard] != {"type": "field", "inboundTag": [INBOUND], "outboundTag": "blocked", "ruleTag": GUARD}:
        raise ValueError("Authorization guard changed")
    result = []
    for rule in rules[:guard]:
        if deployment.data["mode"] == "single" and rule == {"type": "field", "inboundTag": ["rpk-dns"], "ip": [deployment.data.get("dns_ipv4", "1.1.1.1")], "port": "53", "network": "udp", "outboundTag": "direct"}:
            continue
        if rule.get("inboundTag") == ["api"] and rule.get("outboundTag") == "api":
            continue
        if rule.get("outboundTag") == "blocked":
            continue
        tag = rule.get("ruleTag", "")
        if not tag.startswith(ACL) or rule.get("inboundTag") != [INBOUND] or len(rule.get("user", [])) != 1:
            raise ValueError("A native route could bypass account authorization")
        if set(rule) != {"type", "inboundTag", "user", "vlessRoute", "outboundTag", "ruleTag"} or not rule["user"][0].startswith("vless-id:"):
            raise ValueError("Unexpected authorization rule")
        rid = tag.rsplit(":", 1)[-1]
        route = deployment.active_routes.get(rid)
        if not route or rule.get("vlessRoute") != str(route["number"]) or rule.get("outboundTag") != route["exit"]:
            raise ValueError("Authorization route identity changed")
        if rules.index(required_private) > rules.index(rule):
            raise ValueError("Destination guard must precede grants")
        prefix = ACL + account["id"] + ":"
        if tag.startswith(prefix) and rule["user"] == [identities.routing_user(account["uuid"])]:
            rid = tag[len(prefix):]
            route = deployment.active_routes.get(rid)
            if route and rule.get("vlessRoute") == str(route["number"]) and rule.get("outboundTag") == route["exit"]:
                result.append(rid)
    return sorted(set(result)) if account["enabled"] else []


def nginx_config(deployment):
    """Dedicated managed host config. No public management locations exist."""
    d = deployment.data
    if not d.get("web", {}).get("enabled"):
        return None
    hostname = d["web"]["domain"]
    http_v6 = "listen [::]:80 ipv6only=on;" if deployment.entry.get("ipv6") else ""
    stream = ""
    if deployment.front_stream:
        names = "\n".join("        " + n + " 127.0.0.1:9443;" for n in d["reality"]["server_names"])
        v6 = "listen [::]:443 ipv6only=on;" if deployment.entry.get("ipv6") else ""
        stream = f'''stream {{
    map $ssl_preread_server_name $rpk_backend {{
        default 127.0.0.1:9444;
        {hostname} 127.0.0.1:8444;
{names}
    }}
    server {{ listen 443; {v6} ssl_preread on; proxy_protocol on;
        proxy_pass $rpk_backend; proxy_connect_timeout 5s; proxy_timeout 3600s; }}
    server {{ listen 127.0.0.1:9444; return ""; }}
}}
'''
    subs = ""
    if d.get("subscriptions"):
        subs = '''        location ~ ^/(s|m|x)/[A-Za-z0-9_-]{16,128}$ {
            error_log /dev/null crit;
            limit_req zone=rpk_sub burst=10 nodelay;
            proxy_pass http://127.0.0.1:2097;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For "";
            proxy_hide_header Set-Cookie;
            add_header Cache-Control "private, no-store" always;
            add_header Referrer-Policy "no-referrer" always;
        }
'''
    return f'''# Managed by Reality Proxy Kit; public management is deliberately absent.
include /etc/nginx/modules-enabled/*.conf;
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
events {{ worker_connections 1024; }}
{stream}http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    limit_req_zone $binary_remote_addr zone=rpk_sub:10m rate=5r/s;
    server {{
        listen 80;
        {http_v6}
        server_name {hostname};
        if ($host != {hostname}) {{ return 444; }}
        location /.well-known/acme-challenge/ {{ root /var/lib/reality-proxy-kit/acme; }}
        location / {{ return 301 https://{hostname}$request_uri; }}
    }}
    server {{
        listen 127.0.0.1:8444 ssl http2 proxy_protocol;
        server_name {hostname};
        ssl_certificate /etc/reality-proxy-kit/tls/fullchain.pem;
        ssl_certificate_key /etc/reality-proxy-kit/tls/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        root /var/www/reality-proxy-kit;
        add_header X-Content-Type-Options nosniff always;
        location ~ ^/(admin|panel|login|manager)(/|$) {{ return 404; }}
        location ~ /\\. {{ return 404; }}
{subs}        location / {{ try_files $uri $uri/ =404; }}
    }}
}}
'''


def core_unit():
    return '''[Unit]
Description=Reality Proxy Kit entry
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=rpk
Group=rpk
Environment=UTENASAMA_REALITY_LEGACY_X25519=1
Environment=RPK_VLESS_IDENTITY_ROUTING=1
ExecStart=/usr/local/lib/reality-proxy-kit/xray run -c /etc/reality-proxy-kit/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
'''


def exit_unit():
    return '''[Unit]
Description=Reality Proxy Kit SS2022 exit
After=network-online.target
Wants=network-online.target
[Service]
User=rpk
Group=rpk
ExecStart=/usr/local/bin/sing-box run -c /etc/reality-proxy-kit/sing-box.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
'''
