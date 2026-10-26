#!/usr/bin/env python3
"""Black-box NAT behavior check for the lab, independent of Pierce's own C++ STUN code.

  server: runs in the obs namespace on 203.0.113.10:3478, 203.0.113.10:3479, 203.0.113.11:3478
  client: runs in a peer namespace and classifies its NAT as
          full | restricted | port-restricted | symmetric

Client procedure (each run uses fresh local ports, so earlier runs do not leak into the filter state):
  1. From port P, ask 10:3478 what our public endpoint is            -> M1
  2. Ask the server to send to M1 from a different IP   (11:3478)    -> arrives? full cone
  3. Ask the server to send to M1 from a different port (10:3479)    -> arrives? restricted
  4. From port Q, ask 10:3478 and then 11:3478                       -> ports differ? symmetric
     (separate socket so step 4 does not open the filter for steps 2-3)

This is lab scaffolding to prove the lab is correct. It is not the detector the roadmap asks for.
"""
import os
import socket
import sys

IP1, IP2 = "203.0.113.10", "203.0.113.11"
MAIN, ALT = 3478, 3479


def server() -> None:
    socks = {}
    for ip, port in ((IP1, MAIN), (IP1, ALT), (IP2, MAIN)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, port))
        socks[(ip, port)] = s
    from selectors import DefaultSelector, EVENT_READ

    sel = DefaultSelector()
    for s in socks.values():
        sel.register(s, EVENT_READ)
    while True:
        for key, _ in sel.select():
            s = key.fileobj
            data, (rip, rport) = s.recvfrom(1500)
            parts = data.decode(errors="replace").split()
            if not parts:
                continue
            if parts[0] == "MAP":  # MAP <nonce>
                s.sendto(f"MAPPED {rip} {rport} {parts[1]}".encode(), (rip, rport))
            elif parts[0] == "SEND_FROM" and len(parts) == 3:  # SEND_FROM other_ip|other_port <nonce>
                src = (IP2, MAIN) if parts[1] == "other_ip" else (IP1, ALT)
                socks[src].sendto(f"HELLO {parts[2]}".encode(), (rip, rport))


def ask(sock: socket.socket, dst, msg: str, expect: str, tries: int = 3):
    for _ in range(tries):
        sock.sendto(msg.encode(), dst)
        try:
            while True:
                data, _ = sock.recvfrom(1500)
                parts = data.decode().split()
                if parts and parts[-1] == expect:
                    return parts
        except socket.timeout:
            continue
    return None


def classify() -> str:
    def fresh() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        s.settimeout(0.4)
        return s

    def nonce() -> str:
        return os.urandom(4).hex()

    q = fresh()
    a = ask(q, (IP1, MAIN), f"MAP {(n := nonce())}", n)
    b = ask(q, (IP2, MAIN), f"MAP {(n := nonce())}", n)
    if not a or not b:
        return "error-no-response"
    if a[2] != b[2]:
        return "symmetric"

    p = fresh()
    if not ask(p, (IP1, MAIN), f"MAP {(n := nonce())}", n):
        return "error-no-response"
    # SEND_FROM gets no reply on the control socket; the probe arrives (or not) as HELLO <nonce>.
    if ask(p, (IP1, MAIN), f"SEND_FROM other_ip {(n := nonce())}", n):
        return "full"
    if ask(p, (IP1, MAIN), f"SEND_FROM other_port {(n := nonce())}", n):
        return "restricted"
    return "port-restricted"


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "server":
        server()
    elif len(sys.argv) >= 2 and sys.argv[1] == "client":
        print(classify())
    else:
        sys.exit("usage: natcheck.py server|client")
