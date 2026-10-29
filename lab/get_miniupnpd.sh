#!/usr/bin/env bash
# Fetch miniupnpd (UPnP IGD + NAT-PMP + PCP daemon, nftables build) for the lab's PORTMAP routers.
#   ./lab/get_miniupnpd.sh            -> build/miniupnpd/usr/sbin/miniupnpd   (no root needed)
# The package is only downloaded and unpacked, never installed: installing it would add a system
# service that programs the HOST's nftables (next to Docker and Nginx Proxy Manager on OCI). The lab
# runs the binary inside its NAT namespaces only. Needs libnftnl11 and libmnl0 (installed with nft).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dest=${PIERCE_BUILD:-"$here/../build"}/miniupnpd
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$tmp" && apt-get download miniupnpd-nftables >/dev/null)
rm -rf "$dest"
dpkg -x "$tmp"/miniupnpd-nftables_*.deb "$dest"
"$dest/usr/sbin/miniupnpd" --version 2>&1 | head -1 || true
echo "unpacked to $dest (not installed)"
