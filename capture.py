#!/usr/bin/env python3
"""
Network Highway — backend packet capture.

Sniffs live traffic with scapy and streams one JSON event per packet to the
frontend over a WebSocket (default ws://localhost:8765).

Run with admin/root privileges:
    Windows :  (Admin terminal, Npcap installed)  python capture.py
    Linux   :  sudo python3 capture.py
    macOS   :  sudo python3 capture.py

Options:
    --iface  <name>   capture on a specific interface (default: scapy's default)
    --port   <int>    WebSocket port (default 8765)
    --filter <bpf>    extra BPF filter, e.g. "tcp or udp"
    --loopback        also include 127.0.0.1 traffic (off by default)
"""

import argparse
import asyncio
import json
import socket
import struct
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

try:
    import websockets
except ImportError:
    raise SystemExit("Missing dependency: pip install websockets")

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, Raw
except ImportError:
    raise SystemExit("Missing dependency: pip install scapy  (Windows also needs Npcap)")

# Ports whose traffic we treat as encrypted / "secure convoy"
SECURE_PORTS = {22, 443, 465, 563, 853, 993, 995, 4433, 5061, 8443}

BATCH_INTERVAL = 0.1      # seconds between WebSocket pushes
BATCH_MAX = 80            # max packet events per push (rest is sampled)
QUEUE_SOFT_LIMIT = 600    # trim queue beyond this to stay realtime

pending = deque(maxlen=4000)   # packet events waiting to be broadcast
clients = set()                # connected WebSocket clients
host_cache = {}                # remote_ip -> domain name (from SNI or rDNS)
rdns_requested = set()
rdns_pool = ThreadPoolExecutor(max_workers=8)
stats = {"captured": 0, "sent": 0, "trimmed": 0}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def get_local_ips():
    """Best-effort set of this machine's IP addresses (to tell in from out)."""
    ips = {"127.0.0.1", "::1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # no traffic actually sent
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0].split("%")[0])
    except OSError:
        pass
    return ips


def extract_sni(payload: bytes):
    """Pull the server name out of a TLS ClientHello, if this payload is one."""
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        idx = 9                                   # record hdr(5) + handshake hdr(4)
        idx += 2 + 32                             # client version + random
        idx += 1 + payload[idx]                   # session id
        idx += 2 + struct.unpack("!H", payload[idx:idx + 2])[0]   # cipher suites
        idx += 1 + payload[idx]                   # compression methods
        if idx + 2 > len(payload):
            return None
        ext_end = idx + 2 + struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2
        while idx + 4 <= min(ext_end, len(payload)):
            etype, elen = struct.unpack("!HH", payload[idx:idx + 4])
            idx += 4
            if etype == 0 and idx + 5 <= len(payload):            # server_name
                name_len = struct.unpack("!H", payload[idx + 3:idx + 5])[0]
                name = payload[idx + 5:idx + 5 + name_len]
                return name.decode("ascii", "ignore") or None
            idx += elen
    except Exception:
        return None
    return None


def rdns_lookup(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            host_cache.setdefault(ip, name)
    except OSError:
        pass


def resolve_host(ip):
    """Return cached name for ip; kick off a background rDNS lookup if new."""
    name = host_cache.get(ip)
    if name is None and ip not in rdns_requested:
        rdns_requested.add(ip)
        rdns_pool.submit(rdns_lookup, ip)
    return name


# --------------------------------------------------------------------------
# Packet handling (runs on scapy's sniffer thread)
# --------------------------------------------------------------------------

def make_on_packet(local_ips, include_loopback):
    def on_packet(pkt):
        if IP in pkt:
            net = pkt[IP]
        elif IPv6 in pkt:
            net = pkt[IPv6]
        else:
            return

        src, dst = net.src, net.dst
        if not include_loopback and (src.startswith("127.") or dst.startswith("127.")
                                     or src == "::1" or dst == "::1"):
            return

        direction = "out" if src in local_ips else "in"
        remote = dst if direction == "out" else src

        sport = dport = None
        proto = "OTHER"
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        secure = bool({sport, dport} & SECURE_PORTS)

        # TLS ClientHello carries the real domain name (SNI) — grab it.
        if proto == "TCP" and secure and direction == "out" and Raw in pkt:
            sni = extract_sni(bytes(pkt[Raw].load))
            if sni:
                host_cache[remote] = sni

        ev = {
            "ts": round(time.time(), 3),
            "dir": direction,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "size": len(pkt),
            "secure": secure,
            "remote": remote,
            "host": resolve_host(remote),
        }
        stats["captured"] += 1
        pending.append(ev)

    return on_packet


# --------------------------------------------------------------------------
# WebSocket server
# --------------------------------------------------------------------------

async def ws_handler(ws):
    clients.add(ws)
    try:
        await ws.send(json.dumps({"type": "hello", "server": "network-highway", "ts": time.time()}))
        async for _ in ws:      # we don't expect messages; keep the socket open
            pass
    finally:
        clients.discard(ws)


async def broadcast_loop():
    while True:
        await asyncio.sleep(BATCH_INTERVAL)
        if not pending:
            continue

        # Stay realtime under load: trim a backlog instead of lagging behind.
        while len(pending) > QUEUE_SOFT_LIMIT:
            pending.popleft()
            stats["trimmed"] += 1

        items = []
        while pending and len(items) < BATCH_MAX:
            items.append(pending.popleft())

        if not clients or not items:
            continue

        msg = json.dumps({"type": "packets", "items": items, "backlog": len(pending)})
        stats["sent"] += len(items)
        websockets.broadcast(clients, msg)


async def main():
    ap = argparse.ArgumentParser(description="Network Highway backend")
    ap.add_argument("--iface", default=None, help="interface to sniff (default: auto)")
    ap.add_argument("--port", type=int, default=8765, help="WebSocket port")
    ap.add_argument("--filter", default="ip or ip6", help="BPF capture filter")
    ap.add_argument("--loopback", action="store_true", help="include 127.0.0.1 traffic")
    args = ap.parse_args()

    local_ips = get_local_ips()
    print("Network Highway backend")
    print(f"  Local IPs   : {', '.join(sorted(local_ips))}")
    print(f"  Interface   : {args.iface or '(scapy default)'}")
    print(f"  WebSocket   : ws://localhost:{args.port}")
    print("  Now open frontend/index.html in a browser — it connects automatically.")
    print("  Ctrl+C to stop.\n")

    sniffer = AsyncSniffer(
        prn=make_on_packet(local_ips, args.loopback),
        store=False,
        iface=args.iface,
        filter=args.filter,
    )
    sniffer.start()

    async with websockets.serve(ws_handler, "localhost", args.port):
        try:
            await broadcast_loop()
        finally:
            sniffer.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\nStopped. Captured {stats['captured']} packets, streamed {stats['sent']}.")
