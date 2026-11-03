#include <gtest/gtest.h>

#include <thread>

#include "stun/detector.hpp"
#include "stun/server.hpp"

using stun::Endpoint;
using stun::NatType;
using stun::Observations;

namespace {
Observations cone(bool from_other_ip, bool from_other_port) {
  Observations o;
  o.mapped_primary = o.mapped_alt_ip = o.mapped_alt_port = Endpoint{{198, 51, 100, 7}, 40000};
  o.reached_from_other_ip = from_other_ip;
  o.reached_from_other_port = from_other_port;
  return o;
}
Observations symmetric(std::uint16_t p1, std::uint16_t p2, std::uint16_t p3) {
  Observations o;
  o.mapped_primary = Endpoint{{198, 51, 100, 7}, p1};
  o.mapped_alt_ip = Endpoint{{198, 51, 100, 7}, p2};
  o.mapped_alt_port = Endpoint{{198, 51, 100, 7}, p3};
  return o;
}
}  // namespace

TEST(Classify, ConeTypesByFiltering) {
  EXPECT_EQ(stun::classify(cone(true, true)), NatType::Full);
  EXPECT_EQ(stun::classify(cone(false, true)), NatType::Restricted);
  EXPECT_EQ(stun::classify(cone(false, false)), NatType::PortRestricted);
}

TEST(Classify, SymmetricSequentialVsRandom) {
  EXPECT_EQ(stun::classify(symmetric(20000, 20001, 20002)), NatType::SymmetricSequential);
  EXPECT_EQ(stun::classify(symmetric(20010, 20006, 20002)), NatType::SymmetricSequential);
  EXPECT_EQ(stun::classify(symmetric(41234, 1789, 59001)), NatType::SymmetricRandom);
  EXPECT_EQ(stun::classify(symmetric(20000, 20001, 20005)), NatType::SymmetricRandom);  // uneven
  EXPECT_EQ(stun::classify(symmetric(20000, 20100, 20200)), NatType::SymmetricRandom);  // too far
}

TEST(Classify, MissingResponseIsUnknown) {
  auto o = cone(false, false);
  o.mapped_alt_ip.reset();
  EXPECT_EQ(stun::classify(o), NatType::Unknown);
  EXPECT_EQ(stun::to_string(NatType::Unknown), "no-response");
}

TEST(Server, AnswersBindingWithSenderAddress) {
  stun::Message req;
  req.type = stun::kBindingRequest;
  req.tid = stun::random_tid();
  req.change_request = stun::kChangePort;
  const Endpoint from{{192, 0, 2, 9}, 5555};
  auto r = stun::handle_request(stun::encode(req), from);
  ASSERT_TRUE(r);
  EXPECT_EQ(r->response.type, stun::kBindingResponse);
  EXPECT_EQ(r->response.tid, req.tid);
  EXPECT_EQ(r->response.xor_mapped, from);
  EXPECT_FALSE(r->change_ip);
  EXPECT_TRUE(r->change_port);
}

TEST(Server, IgnoresNonRequests) {
  stun::Message resp;
  resp.type = stun::kBindingResponse;
  EXPECT_FALSE(stun::handle_request(stun::encode(resp), {}));
  const std::vector<std::uint8_t> junk(30, 0xAB);
  EXPECT_FALSE(stun::handle_request(junk, {}));
}

// Without a NAT in between, the detector talks to a fake server on loopback. The fake answers
// from one socket only, so CHANGE-REQUEST replies come from the "wrong" address but still
// arrive: with no NAT, nothing filters, and the result must be "full".
TEST(Detector, NoNatOnLoopbackLooksLikeFullCone) {
  stun::UdpSocket server(Endpoint{{127, 0, 0, 1}, 0});
  stun::UdpSocket server_alt_port(Endpoint{{127, 0, 0, 1}, 0});
  const auto primary = server.local_endpoint();
  const auto alt_port = server_alt_port.local_endpoint().port;

  std::jthread serve([&](std::stop_token stop) {
    while (!stop.stop_requested()) {
      for (auto* s : {&server, &server_alt_port}) {
        auto d = s->receive(std::chrono::milliseconds(5));
        if (!d) continue;
        if (auto r = stun::handle_request(d->bytes, d->from))
          s->send_to(stun::encode(r->response), d->from);
      }
    }
  });

  // 127.0.0.2 is also loopback on Linux, but nobody listens there: the "alternate IP" mapping
  // request would time out, so point the alternate IP at the primary one.
  stun::DetectorConfig cfg{primary, primary.v4(), alt_port, std::chrono::milliseconds(100), 2};
  stun::Detector det(cfg);
  const auto o = det.observe();
  ASSERT_TRUE(o.mapped_primary);
  EXPECT_EQ(o.mapped_primary->port, o.mapped_alt_port->port);
  EXPECT_EQ(stun::classify(o), NatType::Full);
}
