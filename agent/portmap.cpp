#include "agent/portmap.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

#include "agent/pcp.hpp"

#ifdef PIERCE_HAVE_NATPMP
#include <natpmp.h>
#endif
#ifdef PIERCE_HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#endif

namespace agent {
namespace {

using Clock = std::chrono::steady_clock;
using Ipv4 = std::array<std::uint8_t, 4>;

std::chrono::milliseconds left(Clock::time_point deadline) {
  return std::max(std::chrono::milliseconds(0),
                  std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()));
}

// A UDP socket connected to gateway:port. "Connected" matters: if nothing listens there, the
// gateway's ICMP port unreachable comes back as ECONNREFUSED, so a missing service fails at once
// instead of after a timeout.
struct ConnectedUdp {
  int fd = -1;
  ConnectedUdp(const Ipv4& ip, std::uint16_t port) {
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    std::memcpy(&sa.sin_addr, ip.data(), 4);
    if (fd >= 0 && connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) < 0) {
      close(fd);
      fd = -1;
    }
  }
  ~ConnectedUdp() {
    if (fd >= 0) close(fd);
  }
  Ipv4 local_ip() const {
    sockaddr_in sa{};
    socklen_t len = sizeof sa;
    getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    Ipv4 ip{};
    std::memcpy(ip.data(), &sa.sin_addr, 4);
    return ip;
  }
  bool refused = false;  // the last ask() got ICMP port unreachable: nothing listens there
  // Sends `req` and waits for one reply, retransmitting every 250 ms until the deadline.
  std::optional<std::vector<std::uint8_t>> ask(std::span<const std::uint8_t> req, Clock::time_point deadline) {
    refused = false;
    while (Clock::now() < deadline) {
      if (send(fd, req.data(), req.size(), 0) < 0) {
        refused = errno == ECONNREFUSED;
        return std::nullopt;
      }
      pollfd p{fd, POLLIN, 0};
      const int wait = static_cast<int>(std::min<long long>(250, left(deadline).count()));
      if (poll(&p, 1, wait) <= 0) continue;
      std::vector<std::uint8_t> buf(1500);
      const ssize_t n = recv(fd, buf.data(), buf.size(), 0);
      if (n < 0) {
        refused = errno == ECONNREFUSED;
        return std::nullopt;
      }
      buf.resize(static_cast<std::size_t>(n));
      return buf;
    }
    return std::nullopt;
  }
};

}  // namespace

std::string_view to_string(PortMapProtocol p) {
  switch (p) {
    case PortMapProtocol::Pcp: return "pcp";
    case PortMapProtocol::NatPmp: return "natpmp";
    case PortMapProtocol::Upnp: return "upnp";
  }
  return "?";
}

std::optional<std::vector<PortMapProtocol>> parse_portmap(std::string_view s) {
  using P = PortMapProtocol;
  if (s == "auto") return std::vector<P>{P::Pcp, P::NatPmp, P::Upnp};
  if (s == "off") return std::vector<P>{};
  if (s == "pcp") return std::vector<P>{P::Pcp};
  if (s == "natpmp") return std::vector<P>{P::NatPmp};
  if (s == "upnp") return std::vector<P>{P::Upnp};
  return std::nullopt;
}

std::optional<Ipv4> default_gateway() {
  // Columns: Iface Destination Gateway Flags ...; addresses as little-endian hex.
  std::ifstream f("/proc/net/route");
  std::string line;
  std::getline(f, line);  // header
  while (std::getline(f, line)) {
    std::istringstream in(line);
    std::string iface, dest, gw;
    if (!(in >> iface >> dest >> gw) || dest != "00000000") continue;
    const auto v = static_cast<std::uint32_t>(std::stoul(gw, nullptr, 16));
    return Ipv4{std::uint8_t(v), std::uint8_t(v >> 8), std::uint8_t(v >> 16), std::uint8_t(v >> 24)};
  }
  return std::nullopt;
}

std::optional<PortMapping> PortMapping::create(std::uint16_t internal_port,
                                               const std::vector<PortMapProtocol>& order,
                                               std::chrono::milliseconds budget,
                                               std::uint32_t lifetime_s) {
  const auto gw = default_gateway();
  if (!gw || order.empty()) return std::nullopt;
  const auto deadline = Clock::now() + budget;
  PortMapping m;
  m.gateway_ = *gw;
  m.internal_port_ = internal_port;
  // PCP and NAT-PMP share UDP 5351. If the PCP probe got "port unreachable", nothing listens
  // there and NAT-PMP is not worth a second probe. (A NAT-PMP-only router does answer a PCP
  // request, with an "unsupported version" error, RFC 6887 §9, so it is still found.)
  bool port_5351_closed = false;

  for (const auto proto : order) {
    if (Clock::now() >= deadline) break;
    m.protocol_ = proto;
    if (proto == PortMapProtocol::Pcp) {
      ConnectedUdp s(*gw, pcp::kServerPort);
      if (s.fd < 0) continue;
      pcp::MapRequest req;
      req.client_ip = s.local_ip();
      req.internal_port = internal_port;
      req.suggested_external_port = internal_port;
      req.lifetime_s = lifetime_s;
      RAND_bytes(req.nonce.data(), static_cast<int>(req.nonce.size()));
      const auto bytes = pcp::encode(req);
      auto reply = s.ask(bytes, deadline);
      port_5351_closed = s.refused;
      if (!reply) continue;
      auto r = pcp::decode(*reply, req.nonce);
      if (!r || r->result != 0) continue;
      m.client_ip_ = req.client_ip;
      m.pcp_nonce_ = req.nonce;
      m.external_ = {r->external_ip, r->external_port};
      m.active_ = true;
      return m;
    }
#ifdef PIERCE_HAVE_NATPMP
    if (proto == PortMapProtocol::NatPmp) {
      if (port_5351_closed) continue;
      natpmp_t n;
      in_addr_t gw_addr;
      std::memcpy(&gw_addr, gw->data(), 4);
      if (initnatpmp(&n, 1, gw_addr) < 0) continue;
      // libnatpmp retransmits on its own schedule; we only bound the total time.
      auto wait_response = [&](natpmpresp_t& resp) {
        int r;
        do {
          fd_set fds;
          FD_ZERO(&fds);
          FD_SET(n.s, &fds);
          timeval tv{};
          getnatpmprequesttimeout(&n, &tv);
          const auto ms = std::min<long long>(left(deadline).count(), tv.tv_sec * 1000 + tv.tv_usec / 1000);
          tv = {static_cast<time_t>(ms / 1000), static_cast<suseconds_t>((ms % 1000) * 1000)};
          select(n.s + 1, &fds, nullptr, nullptr, &tv);
          r = readnatpmpresponseorretry(&n, &resp);
        } while (r == NATPMP_TRYAGAIN && Clock::now() < deadline);
        return r == 0;
      };
      natpmpresp_t resp{};
      bool ok = sendpublicaddressrequest(&n) >= 0 && wait_response(resp) &&
                resp.type == NATPMP_RESPTYPE_PUBLICADDRESS;
      Ipv4 ext_ip{};
      if (ok) std::memcpy(ext_ip.data(), &resp.pnu.publicaddress.addr, 4);
      ok = ok && sendnewportmappingrequest(&n, NATPMP_PROTOCOL_UDP, internal_port, internal_port,
                                           lifetime_s) >= 0 &&
           wait_response(resp) && resp.type == NATPMP_RESPTYPE_UDPPORTMAPPING;
      closenatpmp(&n);
      if (!ok) continue;
      m.external_ = {ext_ip, resp.pnu.newportmapping.mappedpublicport};
      m.active_ = true;
      return m;
    }
#endif
#ifdef PIERCE_HAVE_MINIUPNPC
    if (proto == PortMapProtocol::Upnp) {
      // Discovery: an SSDP M-SEARCH sent straight to the gateway (unicast search, UPnP 1.1)
      // instead of to the multicast group, so a router without UPnP fails at once.
      ConnectedUdp s(*gw, 1900);
      if (s.fd < 0) continue;
      char gw_text[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, gw->data(), gw_text, sizeof gw_text);
      const std::string search = std::string("M-SEARCH * HTTP/1.1\r\nHOST: ") + gw_text +
                                 ":1900\r\nMAN: \"ssdp:discover\"\r\n"
                                 "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
      auto reply = s.ask(std::span(reinterpret_cast<const std::uint8_t*>(search.data()), search.size()), deadline);
      if (!reply) continue;
      std::string text(reply->begin(), reply->end()), location;
      std::istringstream lines(text);
      for (std::string l; std::getline(lines, l);) {
        if (l.size() > 9 && strncasecmp(l.c_str(), "LOCATION:", 9) == 0) {
          location = l.substr(9);
          location.erase(0, location.find_first_not_of(' '));
          while (!location.empty() && (location.back() == '\r' || location.back() == ' ')) location.pop_back();
        }
      }
      if (location.empty()) continue;
      // The rest (device description, SOAP calls) is miniupnpc's.
      UPNPUrls urls{};
      IGDdatas data{};
      char lanaddr[64] = {};
      if (UPNP_GetIGDFromUrl(location.c_str(), &urls, &data, lanaddr, sizeof lanaddr) != 1) continue;
      char ext_ip_text[40] = {};
      const std::string port = std::to_string(internal_port), lease = std::to_string(lifetime_s);
      const bool ok =
          UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, ext_ip_text) == UPNPCOMMAND_SUCCESS &&
          UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port.c_str(), port.c_str(), lanaddr,
                              "pierce", "UDP", nullptr, lease.c_str()) == UPNPCOMMAND_SUCCESS;
      if (ok) {
        m.upnp_control_url_ = urls.controlURL;
        m.upnp_service_type_ = data.first.servicetype;
      }
      FreeUPNPUrls(&urls);
      in_addr ext{};
      if (!ok || inet_pton(AF_INET, ext_ip_text, &ext) != 1) continue;
      Ipv4 ip{};
      std::memcpy(ip.data(), &ext, 4);
      m.external_ = {ip, internal_port};
      m.active_ = true;
      return m;
    }
#endif
  }
  return std::nullopt;
}

PortMapping::PortMapping(PortMapping&& o) noexcept
    : protocol_(o.protocol_), external_(o.external_), internal_port_(o.internal_port_),
      gateway_(o.gateway_), client_ip_(o.client_ip_), pcp_nonce_(o.pcp_nonce_),
      upnp_control_url_(std::move(o.upnp_control_url_)),
      upnp_service_type_(std::move(o.upnp_service_type_)), active_(std::exchange(o.active_, false)) {}

PortMapping::~PortMapping() {
  if (!active_) return;
  // Best effort, briefly: the mapping would expire on its own after its lifetime anyway.
  const auto deadline = Clock::now() + std::chrono::milliseconds(300);
  if (protocol_ == PortMapProtocol::Pcp) {
    ConnectedUdp s(gateway_, pcp::kServerPort);
    pcp::MapRequest req{client_ip_, internal_port_, 0, 0, pcp_nonce_};  // lifetime 0 = delete
    if (s.fd >= 0) s.ask(pcp::encode(req), deadline);
  }
#ifdef PIERCE_HAVE_NATPMP
  if (protocol_ == PortMapProtocol::NatPmp) {
    natpmp_t n;
    in_addr_t gw_addr;
    std::memcpy(&gw_addr, gateway_.data(), 4);
    if (initnatpmp(&n, 1, gw_addr) >= 0) {
      sendnewportmappingrequest(&n, NATPMP_PROTOCOL_UDP, internal_port_, 0, 0);
      natpmpresp_t resp;
      pollfd p{n.s, POLLIN, 0};
      if (poll(&p, 1, 300) > 0) readnatpmpresponseorretry(&n, &resp);
      closenatpmp(&n);
    }
  }
#endif
#ifdef PIERCE_HAVE_MINIUPNPC
  if (protocol_ == PortMapProtocol::Upnp)
    UPNP_DeletePortMapping(upnp_control_url_.c_str(), upnp_service_type_.c_str(),
                           std::to_string(external_.port).c_str(), "UDP", nullptr);
#endif
  (void)deadline;
}

}  // namespace agent
