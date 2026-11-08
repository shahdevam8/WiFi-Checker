#!/usr/bin/env python3
"""
Local network device scanner + dashboard server.  Standard library only.

How it works (all on your own machine):
  1. Finds your REAL WiFi/LAN adapter(s). On Windows it asks PowerShell for structured
     data (works in any Windows language) and ignores VPN / VirtualBox / WSL / Hyper-V /
     Bluetooth adapters, whose fake "devices" used to pollute the list.
  2. Pings every address on that subnet, which makes your OS ask "who has this IP?" and
     refresh its neighbor table. Replies are detected language-independently.
  3. Reads the neighbor table (IP <-> MAC) and keeps only real devices on your subnet.
  4. Finds names: mDNS/Bonjour (phones, TVs, speakers) -> router DNS -> NetBIOS (Windows PCs),
     then falls back to manufacturer / "private MAC" labels.
  5. Serves http://localhost:8765. Scans run in the background, so the page never waits on
     them, and it never shows made-up data.

Every scan also writes debug_report.txt next to this file (what the OS actually returned).
"""

import hashlib
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8765
PING_TIMEOUT_MS = 800
PING_WORKERS = 64
MDNS_TIMEOUT_S = 2.5

# A handful of common OUI (MAC prefix) -> vendor mappings, just enough to
# label a device usefully when there's no hostname to go on.
OUI_VENDORS = {
    "3C:22:FB": "Apple", "F0:18:98": "Apple", "A4:5E:60": "Apple",
    "D8:BB:2C": "Apple", "AC:BC:32": "Apple", "9C:B6:D0": "Apple",
    "68:37:E9": "Amazon", "FC:65:DE": "Amazon", "44:65:0D": "Amazon",
    "98:F1:70": "Samsung", "8C:79:F5": "Samsung", "5C:0A:5B": "Samsung",
    "7C:2E:BD": "Sony", "AC:E0:10": "Sony",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "18:FE:34": "Espressif (IoT)", "24:0A:C4": "Espressif (IoT)", "A0:20:A6": "Espressif (IoT)",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Sonos", "54:2A:1B": "Sonos",
    "F4:F5:D8": "Google", "1C:F2:9A": "Google",
    "00:1A:11": "Google", "48:D6:D5": "Google",
    "D0:37:45": "TP-Link", "50:C7:BF": "TP-Link",
    "00:0C:29": "VMware", "08:00:27": "VirtualBox",
}


# ---------------------------------------------------------------------------
# Network discovery
#
# Windows: PowerShell's Get-NetIPAddress / Get-NetNeighbor return structured
# data that does NOT depend on the Windows display language (the old text
# parsing of `arp -a` / `netsh` did). Linux uses `ip -j`. Text parsing is kept
# only as a fallback. Every raw command output is saved so a debug report can
# show exactly what the OS returned.
# ---------------------------------------------------------------------------

MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
JUNK_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}
DEAD_STATES = {"incomplete", "failed", "unreachable", "noarp"}
LIVE_STATES = {"reachable", "delay", "probe", "permanent"}

# Adapters whose neighbors are NOT your WiFi/LAN devices (VPNs, VMs, WSL...).
VIRTUAL_HINTS = (
    "virtualbox", "vmware", "hyper-v", "vethernet", "wsl", "docker", "loopback",
    "bluetooth", "tap-windows", "tap-", "tailscale", "zerotier", "wireguard",
    "nordlynx", "openvpn", "anyconnect", "fortinet", "hamachi", "npcap",
    "pseudo", "host-only", "virtual", "vpn",
)

DEBUG_RAW = {}          # label -> raw command output (saved into debug_report.txt)
_debug_lock = threading.Lock()


def run_cmd(label, cmd, timeout=10):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=timeout)
        out = res.stdout or ""
        if not out.strip() and res.stderr:
            out = "[stderr] " + res.stderr
    except FileNotFoundError:
        out = "[command not found]"
    except subprocess.TimeoutExpired:
        out = "[timed out]"
    except Exception as e:
        out = f"[error: {e}]"
    with _debug_lock:
        DEBUG_RAW[label] = out[:8000]
    return out


def powershell_json(label, script, timeout=20):
    """Run a PowerShell snippet that ends in ConvertTo-Json; return a list of dicts."""
    if not sys.platform.startswith("win"):
        return []
    full = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "$ErrorActionPreference='SilentlyContinue'; " + script)
    out = run_cmd(label, ["powershell", "-NoProfile", "-NonInteractive",
                          "-ExecutionPolicy", "Bypass", "-Command", full], timeout)
    out = out.strip().lstrip("\ufeff")
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def normalize_mac(raw):
    hexs = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    if len(hexs) != 12:
        return None
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).upper()


def is_randomized_mac(mac):
    """Phones/tablets (iOS 14+, Android 10+, Windows 11) use a per-network 'private'
    MAC by default. It has the 'locally administered' bit set and does NOT match
    the hardware MAC printed in the device's settings - that's normal, not wrong."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except Exception:
        return False


def _is_real_lan_ip(ip):
    return bool(ip) and not ip.startswith("127.") and not ip.startswith("169.254.")


def get_local_ip():
    """Last-resort local IP guess (used only if adapter queries fail)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if _is_real_lan_ip(ip):
            return ip
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if _is_real_lan_ip(ip):
            return ip
    except Exception:
        pass
    return None


def _prefix_from_mask(mask):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _make_net(ip, prefix, **extra):
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    d = {"ip": ip, "prefix": prefix, "network": network, "alias": "", "gateway": None,
         "mac": None, "virtual": False, "up": True, "metric": 9999}
    d.update(extra)
    return d


def detect_networks_windows(diag):
    addrs = powershell_json(
        "ps: IPv4 addresses",
        "Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength,"
        "InterfaceIndex,InterfaceAlias | ConvertTo-Json -Compress")
    routes = powershell_json(
        "ps: default routes",
        "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object InterfaceIndex,RouteMetric,NextHop | ConvertTo-Json -Compress")
    adapters = powershell_json(
        "ps: adapters",
        "Get-NetAdapter | Select-Object ifIndex,Name,InterfaceDescription,MacAddress,"
        "HardwareInterface,@{n='Up';e={([string]$_.Status) -eq 'Up'}} | ConvertTo-Json -Compress")
    if not addrs:
        return []

    by_idx = {a.get("ifIndex"): a for a in adapters}
    gw = {}
    for r in routes:
        idx, nh = r.get("InterfaceIndex"), r.get("NextHop")
        metric = r.get("RouteMetric") or 0
        if idx is not None and nh and nh != "0.0.0.0":
            if idx not in gw or metric < gw[idx][0]:
                gw[idx] = (metric, nh)

    found = []
    for a in addrs:
        ip, prefix, idx = a.get("IPAddress"), a.get("PrefixLength"), a.get("InterfaceIndex")
        if not _is_real_lan_ip(ip) or not isinstance(prefix, int):
            continue
        try:
            if not ipaddress.ip_address(ip).is_private:
                continue
        except ValueError:
            continue
        ad = by_idx.get(idx, {})
        desc = f"{ad.get('Name', '')} {ad.get('InterfaceDescription', '')} {a.get('InterfaceAlias', '')}".lower()
        virtual = (ad.get("HardwareInterface") is False) or any(h in desc for h in VIRTUAL_HINTS)
        n = _make_net(ip, prefix,
                      alias=a.get("InterfaceAlias") or ad.get("Name") or "",
                      gateway=gw.get(idx, (None, None))[1],
                      metric=gw.get(idx, (9999, None))[0],
                      mac=normalize_mac(ad.get("MacAddress")),
                      virtual=virtual, up=ad.get("Up", True))
        if n:
            found.append(n)
    return found


def detect_networks_ipconfig(diag):
    """Fallback when PowerShell is unavailable. Language-independent walk of `ipconfig`:
    an adapter header is an unindented line ending in ':', and inside each adapter the
    order is always IPv4 address -> subnet mask -> default gateway, whatever the language."""
    out = run_cmd("ipconfig", ["ipconfig"])
    found, header, last_ip, current = [], "", None, None
    for line in out.splitlines():
        if line.strip() and not line[0].isspace() and line.rstrip().endswith(":"):
            header, last_ip, current = line.strip().rstrip(":"), None, None
            continue
        for q in IP_RE.findall(line):
            prefix = _prefix_from_mask(q) if q.startswith("255.") else None
            if prefix is not None and last_ip:
                current = _make_net(last_ip, prefix, alias=header,
                                    virtual=any(h in header.lower() for h in VIRTUAL_HINTS))
                if current:
                    found.append(current)
                last_ip = None
            elif _is_real_lan_ip(q):
                try:
                    private = ipaddress.ip_address(q).is_private
                except ValueError:
                    private = False
                if current is not None and current["gateway"] is None and prefix is None:
                    current["gateway"] = q          # first address after the mask = default gateway
                    current["metric"] = 25
                    current = None
                elif private:
                    last_ip = q
    return found


def detect_networks_linux(diag):
    try:
        ifaces = json.loads(run_cmd("ip -j addr", ["ip", "-j", "addr"]) or "[]")
        routes = json.loads(run_cmd("ip -j route default", ["ip", "-j", "route", "show", "default"]) or "[]")
    except ValueError:
        return []
    gw = {r.get("dev"): (r.get("metric", 0), r.get("gateway")) for r in routes}
    found = []
    for itf in ifaces:
        name = itf.get("ifname", "")
        if name == "lo":
            continue
        virtual = name.startswith(("docker", "veth", "virbr", "br-", "tun", "tap", "vmnet", "wg", "tailscale", "zt"))
        for ai in itf.get("addr_info", []):
            if ai.get("family") != "inet" or not _is_real_lan_ip(ai.get("local")):
                continue
            try:
                if not ipaddress.ip_address(ai["local"]).is_private:
                    continue
            except ValueError:
                continue
            n = _make_net(ai["local"], ai.get("prefixlen", 24), alias=name,
                          gateway=gw.get(name, (None, None))[1], metric=gw.get(name, (9999, None))[0],
                          mac=normalize_mac(itf.get("address")), virtual=virtual,
                          up=itf.get("operstate", "UP") != "DOWN")
            if n:
                found.append(n)
    return found


def detect_networks(diag):
    """Returns the list of REAL LAN networks this machine is on (primary first)."""
    if sys.platform.startswith("win"):
        found = detect_networks_windows(diag) or detect_networks_ipconfig(diag)
    elif sys.platform.startswith("linux"):
        found = detect_networks_linux(diag)
    else:
        found = []
    if not found:
        ip = get_local_ip()
        if ip:
            n = _make_net(ip, 24)
            found = [n] if n else []
            diag.append("Adapter query failed - guessed network from outbound socket (assuming /24)")

    for n in found:
        n["skip"] = "virtual adapter (VPN/VM/WSL/etc.)" if n["virtual"] else ("adapter is down" if not n["up"] else "")
    chosen = [n for n in found if not n["skip"]]
    if not chosen:                       # nothing looked physical: don't give up, use everything
        chosen = found
        for n in chosen:
            n["skip"] = ""
    with_gw = [n for n in chosen if n["gateway"]]
    chosen = sorted(with_gw or chosen, key=lambda n: n["metric"])

    for n in found:
        used = n in chosen
        diag.append(f"  adapter '{n['alias'] or '?'}': {n['ip']}/{n['prefix']}"
                    f"{' gateway ' + n['gateway'] if n['gateway'] else ''} -> "
                    f"{'USED' if used else 'skipped: ' + (n['skip'] or 'no default gateway')}")
    return chosen[:2]


def sweep_hosts(networks):
    hosts, own = [], {n["ip"] for n in networks}
    for n in networks:
        net = n["network"]
        if net.num_addresses > 1024:      # huge subnet: just sweep the /24 around us
            net = ipaddress.ip_network(f"{n['ip']}/24", strict=False)
        hosts += [str(h) for h in net.hosts() if str(h) not in own]
    return list(dict.fromkeys(hosts))


def ping(ip):
    """True if the host answered. Detected via 'ttl=' in the reply, which is the same
    in every Windows language (the old code ignored replies entirely)."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, (PING_TIMEOUT_MS + 999) // 1000)), ip]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=4)
    except Exception:
        return False
    return "ttl=" in (res.stdout or "").lower()


def ping_sweep(hosts):
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        results = list(pool.map(ping, hosts))
    return {h for h, ok in zip(hosts, results) if ok}


def parse_neighbor_text(text):
    """Fallback parser for `arp -a` / `netsh ... show neighbors`: (ip, mac, state) rows."""
    rows = []
    for line in text.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not (ip_m and mac_m):
            continue
        st = re.search(r"\b(reachable|stale|delay|probe|permanent|incomplete|unreachable|failed)\b", line, re.I)
        rows.append((ip_m.group(1), mac_m.group(0), st.group(1).lower() if st else "unknown"))
    return rows


def read_neighbors(networks, diag):
    """Returns {ip: {"mac", "state"}} for real devices on the chosen networks."""
    rows, source = [], ""
    if sys.platform.startswith("win"):
        data = powershell_json(
            "ps: neighbors",
            "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,"
            "InterfaceIndex,@{n='State';e={[string]$_.State}} | ConvertTo-Json -Compress")
        rows = [(r.get("IPAddress"), r.get("LinkLayerAddress"), (r.get("State") or "").lower()) for r in data]
        source = "PowerShell Get-NetNeighbor"
        if not rows:
            rows = parse_neighbor_text(run_cmd("netsh neighbors", ["netsh", "interface", "ipv4", "show", "neighbors"]))
            source = "netsh (text fallback)"
        if not rows:
            rows = parse_neighbor_text(run_cmd("arp -a", ["arp", "-a"]))
            source = "arp -a (text fallback)"
    else:
        try:
            data = json.loads(run_cmd("ip -j neigh", ["ip", "-j", "neigh", "show"]) or "[]")
            rows = [(r.get("dst"), r.get("lladdr"), " ".join(r.get("state", [])).lower()) for r in data]
            source = "ip neigh"
        except ValueError:
            rows = []
        if not rows:
            rows = parse_neighbor_text(run_cmd("arp -a", ["arp", "-a"]))
            source = "arp -a"

    nets = [n["network"] for n in networks]
    kept, dropped = {}, {"dead/incomplete": 0, "multicast/broadcast/link-local": 0, "other subnet": 0, "bad MAC": 0}
    for ip, mac_raw, state in rows:
        mac = normalize_mac(mac_raw)
        if not mac or mac in JUNK_MACS:
            dropped["bad MAC"] += 1
            continue
        if state in DEAD_STATES:
            dropped["dead/incomplete"] += 1
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            continue
        if (addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified
                or any(addr == n.broadcast_address for n in nets)):
            dropped["multicast/broadcast/link-local"] += 1
            continue
        if nets and not any(addr in n for n in nets):
            dropped["other subnet"] += 1
            continue
        kept[ip] = {"mac": mac, "state": state}
    diag.append(f"Neighbor table via {source}: {len(rows)} raw rows -> {len(kept)} kept "
                f"(dropped: {', '.join(f'{v} {k}' for k, v in dropped.items() if v) or 'none'})")
    return kept


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.split(".")[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# mDNS / Bonjour: the actual protocol phones, tablets, smart speakers, and
# Chromecasts use to broadcast their own device name on the LAN. A standard
# reverse-DNS lookup never sees this - it's a separate multicast UDP protocol
# on port 5353. We send one query covering several common service types and
# listen briefly for replies, matching each device's SRV record (its friendly
# name) to its A record (its IP) to build an ip -> name map for the subnet.
# ---------------------------------------------------------------------------

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
MDNS_SERVICE_TYPES = [
    "_device-info._tcp.local.", "_companion-link._tcp.local.",
    "_airplay._tcp.local.", "_raop._tcp.local.", "_googlecast._tcp.local.",
    "_workstation._tcp.local.", "_smb._tcp.local.", "_ipp._tcp.local.",
    "_http._tcp.local.", "_ssh._tcp.local.", "_spotify-connect._tcp.local.",
]


def _encode_dns_name(name):
    out = b""
    for part in name.strip(".").split("."):
        b = part.encode("utf-8", "ignore")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _build_mdns_query(service_types):
    header = struct.pack(">HHHHHH", 0, 0, len(service_types), 0, 0, 0)
    body = b"".join(_encode_dns_name(s) + struct.pack(">HH", 12, 1) for s in service_types)
    return header + body


def _decode_dns_name(data, offset, depth=0):
    """Decodes a (possibly compressed) DNS name. Returns (name, offset_after_it)."""
    labels = []
    jumped = False
    end_offset = None
    while depth < 20 and offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
                jumped = True
            offset = pointer
            depth += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end_offset if end_offset is not None else offset)


def _parse_mdns_response(data, host_to_ip, instance_to_host):
    try:
        _id, _flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[0:12])
    except Exception:
        return
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_dns_name(data, offset)
        offset += 4
    for _ in range(ancount + nscount + arcount):
        if offset >= len(data):
            return
        name, offset = _decode_dns_name(data, offset)
        if offset + 10 > len(data):
            return
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if rdata_start + rdlength > len(data):
            return
        if rtype == 33 and rdlength >= 6:  # SRV: friendly-instance-name -> hostname
            target, _ = _decode_dns_name(data, rdata_start + 6)
            instance_to_host[name] = target
        elif rtype == 1 and rdlength == 4:  # A: hostname -> ip
            host_to_ip[name] = ".".join(str(b) for b in data[rdata_start:rdata_start + 4])
        offset = rdata_start + rdlength


def discover_mdns_names(local_ip=None, timeout=MDNS_TIMEOUT_S):
    """
    One multicast question to the whole subnet: "who offers these services?".
    The query is sent from a normal (non-5353) port, which tells mDNS responders
    to answer us directly by unicast. That works even when Windows' own DNS
    Client service is already holding port 5353, which used to make the old
    listener silently receive nothing. Returns {ip: {"name", "host"}}.
    """
    host_to_ip, instance_to_host = {}, {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        iface = socket.inet_aton(local_ip) if local_ip else socket.inet_aton("0.0.0.0")
        sock.bind((local_ip or "", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.25)
        query = _build_mdns_query(MDNS_SERVICE_TYPES)

        start = time.time()
        sent = 0
        while time.time() - start < timeout:
            if sent < 3 and time.time() - start >= sent * (timeout / 3):
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))   # resend: some devices miss the first
                sent += 1
            try:
                data, _addr = sock.recvfrom(65535)
                _parse_mdns_response(data, host_to_ip, instance_to_host)
            except socket.timeout:
                continue
            except OSError:
                break
    except Exception:
        pass  # multicast blocked/unavailable - other name sources still apply
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    found = {}
    for instance, host in instance_to_host.items():
        ip = host_to_ip.get(host)
        if ip:
            friendly = instance.split("._")[0].strip()
            if friendly:
                found.setdefault(ip, {"name": friendly, "host": host})
    for host, ip in host_to_ip.items():          # devices that sent a hostname but no service name
        if ip not in found and host.endswith(".local"):
            found[ip] = {"name": host[:-6], "host": host}
    return found


def netbios_name(ip, timeout=3.0):
    """Windows computer names come from NetBIOS. `nbtstat -A` asks a device directly.
    The row type column is translated on non-English Windows ('UNIQUE' -> 'EINDEUTIG'...),
    so only the <20>/<00> tag is matched, never the word."""
    if not sys.platform.startswith("win"):
        return None
    try:
        out = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True,
                             errors="replace", timeout=timeout).stdout
    except Exception:
        return None
    for tag in ("20", "00"):
        m = re.search(rf"^\s*([A-Za-z0-9_\-]{{1,15}})\s*<{tag}>", out, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def vendor_for(mac):
    prefix = mac[:8].upper()
    return OUI_VENDORS.get(prefix)


def host_id_for(mac):
    return "host-" + hashlib.md5(mac.encode()).hexdigest()[:6]


def guess_type(vendor, hostname):
    text = f"{vendor or ''} {hostname or ''}".lower()
    if any(k in text for k in ["iphone", "android", "pixel", "galaxy-s", "mobile"]):
        return "phone"
    if any(k in text for k in ["macbook", "laptop", "notebook", "pc-", "desktop"]):
        return "laptop"
    if any(k in text for k in ["tv", "roku", "chromecast", "firetv"]):
        return "tv"
    if any(k in text for k in ["sonos", "echo", "hue", "nest", "speaker"]):
        return "speaker"
    if any(k in text for k in ["playstation", "xbox", "nintendo", "ps5", "ps4"]):
        return "console"
    if vendor in ("Espressif (IoT)", "Raspberry Pi", "Philips Hue"):
        return "unknown"
    return "unknown"


_name_cache = {}   # mac -> (name, source, host): avoids re-running slow lookups every scan


def _dns_then_netbios(ip):
    host = reverse_dns(ip)
    if host:
        return (host, "dns", host)
    nb = netbios_name(ip)
    if nb:
        return (nb, "netbios", nb)
    return None


def resolve_names(neigh, mdns):
    """ip -> (name, source, host). mDNS first, then cached, then DNS/NetBIOS in parallel
    with a hard overall deadline so one silent device can't stall the scan."""
    results, todo = {}, []
    for ip, info in neigh.items():
        if ip in mdns:
            results[ip] = (mdns[ip]["name"], "mdns", mdns[ip]["host"])
        elif info["mac"] in _name_cache:
            results[ip] = _name_cache[info["mac"]]
        else:
            todo.append(ip)
    if todo:
        pool = ThreadPoolExecutor(max_workers=16)
        futures = {ip: pool.submit(_dns_then_netbios, ip) for ip in todo}
        deadline = time.time() + 10
        for ip, fut in futures.items():
            try:
                res = fut.result(timeout=max(0.1, deadline - time.time()))
            except Exception:
                res = None
            if res:
                results[ip] = res
                _name_cache[neigh[ip]["mac"]] = res
        pool.shutdown(wait=False)
    return results


def local_mac_fallback():
    import uuid
    return normalize_mac("%012x" % uuid.getnode())


def make_device(ip, mac, online, name_info=None, is_gateway=False, is_self=False, state=""):
    name, source, host = name_info if name_info else (None, None, None)
    vendor = vendor_for(mac)
    randomized = is_randomized_mac(mac)
    if is_self:
        name, source, host = socket.gethostname(), "this-pc", socket.gethostname()
    if not name:
        if is_gateway:
            name, source = "Router / Gateway", "gateway"
        elif vendor:
            name, source = f"{vendor} device", "vendor-guess"
        elif randomized:
            name, source = "Device (private MAC)", "private-mac"
        else:
            name, source = "Unknown device", "unknown"
    real_name = name if source in ("mdns", "dns", "netbios", "this-pc") else None
    dtype = "router" if is_gateway else ("laptop" if is_self else guess_type(vendor, real_name))
    return {
        "name": name,
        "hostId": host or host_id_for(mac),
        "mac": mac,
        "ip": ip,
        "type": dtype,
        "status": "online" if online else "offline",
        "vendor": vendor,
        "nameSource": source,
        "randomizedMac": randomized,
        "isThisDevice": is_self,
        "isGateway": is_gateway,
        "flagged": source == "unknown",
        "neighborState": state,
    }


def _scan(diag):
    diag.append("Networks found:")
    networks = detect_networks(diag)
    primary = networks[0] if networks else None

    hosts = sweep_hosts(networks)
    responders = set()
    if hosts:
        t0 = time.time()
        responders = ping_sweep(hosts)
        diag.append(f"Ping sweep: {len(hosts)} addresses, {len(responders)} replied ({time.time() - t0:.1f}s)")
    else:
        diag.append("Ping sweep skipped: no usable network detected")

    neigh = read_neighbors(networks, diag)
    mdns = discover_mdns_names(primary["ip"] if primary else None)
    diag.append(f"mDNS: {len(mdns)} device(s) announced a name"
                + ("" if mdns else " (none - multicast may be blocked by a firewall/VPN, or devices don't advertise)"))
    names = resolve_names(neigh, mdns)

    own = {n["ip"]: n for n in networks}
    gateways = {n["gateway"] for n in networks if n["gateway"]}
    devices = []
    for ip, info in neigh.items():
        if ip in own:
            continue
        online = ip in responders or info["state"] in LIVE_STATES
        devices.append(make_device(ip, info["mac"], online, names.get(ip),
                                   is_gateway=ip in gateways, state=info["state"]))
    for ip, n in own.items():     # the ARP table never lists the machine itself
        mac = n["mac"] or local_mac_fallback()
        if mac:
            devices.append(make_device(ip, mac, True, is_self=True))

    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
    counts = {}
    for d in devices:
        counts[d["nameSource"]] = counts.get(d["nameSource"], 0) + 1
    diag.append(f"Devices: {len(devices)} total, {sum(d['status'] == 'online' for d in devices)} online")
    diag.append(f"Name sources: {counts}")

    return {
        "devices": devices,
        "scannedAt": time.time(),
        "subnet": ", ".join(str(n["network"]) for n in networks) or "unknown",
        "localIpDetected": bool(networks),
        "diagnostics": diag,
    }


# ---------------------------------------------------------------------------
# Cache + server. The scan runs OUTSIDE the cache lock, so API requests always
# answer instantly. (Before, the lock was held for the whole 10+ second scan,
# the dashboard's 3-second fetch timed out, and it fell back to SAMPLE data -
# which is what looked like "wrong IPs, wrong MACs, wrong count".)
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_scan_lock = threading.Lock()
_cache = {"devices": [], "scannedAt": 0, "subnet": "", "scanning": True, "hasScanned": False,
          "diagnostics": ["First scan in progress..."], "localIpDetected": False}
_debug_text = "No scan has finished yet."


def build_debug_report(diag, devices):
    lines = ["WiFi viewer debug report",
             time.strftime("%Y-%m-%d %H:%M:%S"),
             f"python {sys.version.split()[0]} on {sys.platform}", "", "SCAN LOG"] + diag + ["", "DEVICES"]
    for d in devices:
        lines.append(f"{d['ip']:<16}{d['mac']:<19}{d['status']:<8}{d['nameSource']:<13}{d['name']}")
    lines += ["", "RAW COMMAND OUTPUT (what the OS actually returned)"]
    with _debug_lock:
        for label, out in DEBUG_RAW.items():
            lines += [f"--- {label} ---", out.strip(), ""]
    return "\n".join(lines)


def refresh_cache():
    global _debug_text
    if not _scan_lock.acquire(blocking=False):
        with _scan_lock:      # a scan is already running: wait for it instead of starting another
            pass
        return
    try:
        with _cache_lock:
            _cache["scanning"] = True
        with _debug_lock:
            DEBUG_RAW.clear()
        diag = []
        try:
            result = _scan(diag)
            result["hasScanned"] = True
        except Exception:
            diag.append("SCAN CRASHED:\n" + traceback.format_exc())
            with _cache_lock:
                result = {"diagnostics": diag, "hasScanned": _cache.get("hasScanned", False)}
            print(diag[-1])
        _debug_text = build_debug_report(diag, result.get("devices", _cache["devices"]))
        try:
            (Path(__file__).parent / "debug_report.txt").write_text(_debug_text, encoding="utf-8")
        except Exception:
            pass
        with _cache_lock:
            _cache.update(result)
        for line in diag:
            print(line)
    finally:
        with _cache_lock:
            _cache["scanning"] = False
        _scan_lock.release()


DISCONNECT_ERRORS = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def handle_error(self, request, client_address):
        pass  # browser reload / closed tab mid-response is normal

    def _write(self, body_bytes):
        try:
            self.wfile.write(body_bytes)
        except DISCONNECT_ERRORS:
            pass

    def _send(self, body, content_type, code=200):
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._write(body)
        except DISCONNECT_ERRORS:
            pass

    def _send_json(self, payload, code=200):
        self._send(json.dumps(payload).encode(), "application/json", code)

    def _snapshot(self):
        with _cache_lock:
            return dict(_cache)

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path == "/api/devices":
                self._send_json(self._snapshot())
            elif path == "/api/rescan":
                refresh_cache()          # waits for the scan; the dashboard allows ~60s for this
                self._send_json(self._snapshot())
            elif path == "/api/debug":
                self._send(_debug_text.encode("utf-8", "replace"), "text/plain; charset=utf-8")
            elif path in ("/", "/index.html"):
                html_path = Path(__file__).parent / "index.html"
                if html_path.exists():
                    self._send(html_path.read_bytes(), "text/html; charset=utf-8")
                else:
                    self._send_json({"error": "index.html not found next to scanner.py"}, 404)
            else:
                self._send_json({"error": "not found"}, 404)
        except DISCONNECT_ERRORS:
            pass


def background_refresh(interval_seconds=30):
    while True:
        refresh_cache()
        time.sleep(interval_seconds)


if __name__ == "__main__":
    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)   # local-only: not exposed to your WiFi
    except OSError:
        print(f"Port {PORT} is already in use - another scanner window is probably still running.")
        print("Close it (or press Ctrl+C in it) and start this again.")
        sys.exit(1)

    threading.Thread(target=background_refresh, daemon=True).start()
    url = f"http://localhost:{PORT}"
    print(f"Dashboard: {url}")
    print("The first scan runs in the background and takes roughly 10-30 seconds.")
    print("If anything looks wrong, open debug_report.txt (created next to this file) and send it over.")
    print("Press Ctrl+C to stop.")
    threading.Timer(1.0, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
