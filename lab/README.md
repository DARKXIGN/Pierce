# NAT lab

Network namespaces create 2 peers, 2 NAT routers, an "internet" bridge and an observer host with two public IPs. The four NAT types are reproduced with nftables. Linux and root required.

```
peerA 10.0.1.2 -- natA 10.0.1.1 | 203.0.113.1 --+
                                                |  bridge br0 (netns pierce-inet)
peerB 10.0.2.2 -- natB 10.0.2.1 | 203.0.113.2 --+
                                                |
                 obs 203.0.113.10, 203.0.113.11 +   two "public servers" (STUN later, self-check now)
```

Everything, including the bridge, lives in its own namespace. The host network, Docker and Nginx Proxy Manager are never touched, and `teardown.sh` removes every trace by deleting the namespaces.

## Usage
```sh
sudo ./lab/setup.sh full symmetric       # natA type, natB type
sudo ./lab/check_ping.sh                 # basic reachability
sudo ./lab/check_nat.sh full symmetric   # black-box NAT behavior check
sudo ./lab/teardown.sh

sudo ./lab/run_matrix.sh                 # all 4×4 combinations → results/lab_selfcheck.csv
```

## NAT types
Terms from RFC 4787: *mapping* decides which public port an internal socket gets; *filtering* decides who may send in.

| Type | Mapping | Inbound filtering | nftables |
|---|---|---|---|
| `full` | endpoint-independent | none | `masquerade` + DNAT all inbound UDP to the LAN host |
| `restricted` | endpoint-independent | remote IPs this ip:port has sent to | same DNAT + dynamic set `contacted` (internal ip . port . remote ip) |
| `port-restricted` | endpoint-independent | remote IP:port pairs this ip:port has sent to | `masquerade`, only `ct state established` |
| `symmetric` | endpoint-dependent (new port per destination) | remote IP:port pairs | `masquerade random`, only `ct state established` |

Approximations to be aware of:
- Endpoint-independent mapping relies on Linux masquerade keeping the source port when it is free. With one LAN host and no port collisions this always holds, so public port = internal port.
- `full`/`restricted` DNAT inbound UDP to the single LAN host on the same port. Fine for a one-host LAN, not a general NAT.
- `symmetric` picks **random** ports. Many real symmetric NATs allocate sequentially; port prediction (stage 3) will need a sequential variant.
- Mapping and `contacted` entries expire after the conntrack UDP timeout / 120 s.

## Self-check (`check_nat.sh`, `natcheck.py`)
A small Python UDP tester that proves the lab behaves as configured, independent of Pierce's own C++ STUN code (so the detector is not validated against itself). A server in `obs` listens on `.10:3478`, `.10:3479` and `.11:3478`; the client in a peer namespace:

1. asks `.10:3478` and `.11:3478` for its public port from one socket — different ports → `symmetric`
2. from a fresh socket, asks `.10:3478` for its mapping, then asks the server to send to it from another IP — arrives → `full`
3. same, from another port on the same IP — arrives → `restricted`, otherwise `port-restricted`

## Last run
All 16 combinations: ping OK and both sides detected as configured (Linux 6.18, Ubuntu 24.04 userland). Re-run on OCI before ticking the roadmap boxes.
