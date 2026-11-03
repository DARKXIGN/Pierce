#!/usr/bin/env python3
"""Measure how long a NAT keeps an idle UDP mapping (roadmap stage 4: "measure the UDP mapping
lifetime of the home router and the phone hotspot; set the keepalive to half of it").

Python 3 standard library only, so the client runs on Windows as it is.

  server (a public host, e.g. OCI):  python3 tools/maplife.py server --port 3490
  client (behind the NAT):           python  tools/maplife.py client --server 1.2.3.4:3490 \
                                         --network home [--runs 3] [--out results/...csv]

How: for each delay t the client opens a fresh UDP socket and sends "reply in t seconds". The
server waits t seconds and answers the address the request came from. The answer gets through
only if the NAT still has that socket's mapping after t idle seconds. All delays run in
parallel, one socket each, so a run takes as long as the longest delay. The lifetime lies
between the longest delay that was answered and the shortest one that was not.

Output: one CSV row per probe, network,run,delay_s,alive. Append to the same file for each
network (home, hotspot, ...).

The server answers only the sender, never with more bytes than the request held (so it cannot be
used for amplification), caps delays at 1800 s and keeps at most 64 pending replies per IP.
"""
import argparse
import csv
import heapq
import os
import selectors
import socket
import sys
import time

MAGIC = b"MAPLIFE1"
MAX_DELAY = 1800
MAX_PENDING_PER_IP = 64
DEFAULT_DELAYS = [10, 20, 30, 45, 60, 90, 120, 180, 240, 300, 450, 600, 900]


def server(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    s.setblocking(False)
    pending = []      # heap of (due_time, seq, addr, payload)
    per_ip = {}
    seq = 0
    print(f"maplife server on UDP {port}", flush=True)
    while True:
        timeout = max(0.0, pending[0][0] - time.monotonic()) if pending else None
        sel = selectors.DefaultSelector()
        sel.register(s, selectors.EVENT_READ)
        if sel.select(timeout):
            while True:
                try:
                    data, addr = s.recvfrom(256)
                except BlockingIOError:
                    break
                # MAGIC | delay (4 ascii digits) | nonce
                if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
                    continue
                try:
                    delay = int(data[len(MAGIC):len(MAGIC) + 4])
                except ValueError:
                    continue
                if not 0 <= delay <= MAX_DELAY or per_ip.get(addr[0], 0) >= MAX_PENDING_PER_IP:
                    continue
                per_ip[addr[0]] = per_ip.get(addr[0], 0) + 1
                seq += 1
                heapq.heappush(pending, (time.monotonic() + delay, seq, addr, data))
        sel.close()
        now = time.monotonic()
        while pending and pending[0][0] <= now:
            _, _, addr, data = heapq.heappop(pending)
            per_ip[addr[0]] -= 1
            try:
                s.sendto(data, addr)  # the same bytes back: never more than was sent
            except OSError:
                pass


def client(server_addr, network: str, runs: int, delays, out: str) -> int:
    host, port = server_addr.rsplit(":", 1)
    dest = (host, int(port))
    longest = max(delays)
    write_header = not os.path.exists(out) or os.path.getsize(out) == 0
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["network", "run", "delay_s", "alive"])
        for run in range(1, runs + 1):
            print(f"run {run}/{runs}: {len(delays)} probes, about {longest // 60} min {longest % 60} s",
                  flush=True)
            socks = {}
            for d in delays:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("0.0.0.0", 0))
                s.setblocking(False)
                nonce = os.urandom(8).hex().encode()
                s.sendto(MAGIC + b"%04d" % d + nonce, dest)
                socks[d] = (s, nonce)
            alive = {d: False for d in delays}
            sel = selectors.DefaultSelector()
            for d, (s, _) in socks.items():
                sel.register(s, selectors.EVENT_READ, d)
            deadline = time.monotonic() + longest + 15
            while time.monotonic() < deadline and not all(alive.values()):
                for key, _ in sel.select(timeout=1.0):
                    d = key.data
                    s, nonce = socks[d]
                    try:
                        data, _ = s.recvfrom(256)
                    except OSError:  # e.g. ICMP-induced errors on Windows
                        continue
                    if data.endswith(nonce):
                        alive[d] = True
                        print(f"  {d:4d} s: answered", flush=True)
            for d in delays:
                w.writerow([network, run, d, int(alive[d])])
                socks[d][0].close()
            f.flush()
            ok = [d for d in delays if alive[d]]
            lost = [d for d in delays if not alive[d]]
            lo = max(ok) if ok else 0
            hi = min((d for d in lost if d > lo), default=None)
            print(f"run {run}: mapping lifetime >= {lo} s" + (f" and < {hi} s" if hi else
                  f" (all {longest} s survived)"), flush=True)
    print(f"wrote {out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("server")
    sp.add_argument("--port", type=int, default=3490)
    cp = sub.add_parser("client")
    cp.add_argument("--server", required=True, help="host:port of the server")
    cp.add_argument("--network", required=True, help="label, e.g. home or hotspot")
    cp.add_argument("--runs", type=int, default=3)
    cp.add_argument("--delays", help="comma-separated seconds (default: 10..900)")
    cp.add_argument("--out", default="results/stage4_mapping_lifetime.csv")
    a = ap.parse_args()
    if a.cmd == "server":
        server(a.port)
        return 0
    delays = [int(x) for x in a.delays.split(",")] if a.delays else DEFAULT_DELAYS
    if any(not 0 <= d <= MAX_DELAY for d in delays):
        sys.exit(f"delays must be within 0..{MAX_DELAY} s")
    return client(a.server, a.network, a.runs, sorted(set(delays)), a.out)


if __name__ == "__main__":
    sys.exit(main())
