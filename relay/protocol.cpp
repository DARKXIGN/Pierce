#include "relay/protocol.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <stdexcept>

namespace relay {
namespace {

constexpr std::size_t kSigned = 24, kMac = 16;

std::array<std::uint8_t, kMac> mac(std::span<const std::uint8_t> data, const Secret& secret) {
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> full{};
  unsigned int len = 0;
  if (!HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), data.data(), data.size(),
            full.data(), &len))
    throw std::runtime_error("HMAC failed");
  std::array<std::uint8_t, kMac> out{};
  std::copy_n(full.begin(), kMac, out.begin());
  return out;
}

void put_u64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 7; i >= 0; --i, v >>= 8) p[i] = static_cast<std::uint8_t>(v);
}
std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

std::vector<std::uint8_t> with_nonce(Type t, std::uint64_t nonce) {
  std::vector<std::uint8_t> out{kMagic, static_cast<std::uint8_t>(t), 0, 0, 0, 0, 0, 0, 0, 0};
  put_u64(out.data() + 2, nonce);
  return out;
}

}  // namespace

TokenBytes issue_token(const Token& t, const Secret& secret) {
  TokenBytes out{};
  std::copy(t.session.begin(), t.session.end(), out.begin());
  put_u64(out.data() + 16, t.expires);
  const auto m = mac(std::span(out).first(kSigned), secret);
  std::copy(m.begin(), m.end(), out.begin() + kSigned);
  return out;
}

std::optional<Token> verify_token(std::span<const std::uint8_t> b, const Secret& secret,
                                  std::uint64_t now) {
  if (b.size() != kTokenSize) return std::nullopt;
  const auto expected = mac(b.first(kSigned), secret);
  if (CRYPTO_memcmp(expected.data(), b.data() + kSigned, kMac) != 0) return std::nullopt;
  Token t;
  std::copy_n(b.begin(), 16, t.session.begin());
  t.expires = get_u64(b.data() + 16);
  if (t.expires <= now) return std::nullopt;
  return t;
}

std::vector<std::uint8_t> bind_message(const TokenBytes& token) {
  std::vector<std::uint8_t> out{kMagic, static_cast<std::uint8_t>(Type::Bind)};
  out.insert(out.end(), token.begin(), token.end());
  return out;
}

std::vector<std::uint8_t> bound_message() { return {kMagic, static_cast<std::uint8_t>(Type::Bound)}; }

std::vector<std::uint8_t> ping_message(std::uint64_t nonce) { return with_nonce(Type::Ping, nonce); }

std::optional<Secret> secret_from_hex(std::string_view hex) {
  if (hex.empty() || hex.size() % 2) return std::nullopt;
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  Secret out;
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = digit(hex[i]), lo = digit(hex[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
  }
  return out;
}

std::optional<std::uint64_t> nonce_of(std::span<const std::uint8_t> b) {
  const auto t = control_type(b);
  if (!t || (*t != Type::Ping && *t != Type::Pong) || b.size() != 10) return std::nullopt;
  return get_u64(b.data() + 2);
}

}  // namespace relay
