#include "agent/probe.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <stdexcept>

namespace probe {
namespace {

constexpr std::size_t kTidOffset = 2, kKindOffset = 14, kMacOffset = 15;

}  // namespace

// HMAC-SHA256 from OpenSSL (never our own crypto), keeping the first 8 of its 32 bytes.
std::array<std::uint8_t, kMacSize> mac8(std::span<const std::uint8_t> data, const Key& key) {
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> full{};
  unsigned int len = 0;
  if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
            full.data(), &len))
    throw std::runtime_error("HMAC failed");
  std::array<std::uint8_t, kMacSize> out{};
  std::copy_n(full.begin(), kMacSize, out.begin());
  return out;
}

TransactionId random_tid() {
  TransactionId tid{};
  if (RAND_bytes(tid.data(), static_cast<int>(tid.size())) != 1)
    throw std::runtime_error("RAND_bytes failed");
  return tid;
}

std::array<std::uint8_t, kSize> encode(const Probe& p, const Key& key) {
  std::array<std::uint8_t, kSize> out{};
  out[0] = kMagic;
  out[1] = kVersion;
  std::copy(p.tid.begin(), p.tid.end(), out.begin() + kTidOffset);
  out[kKindOffset] = static_cast<std::uint8_t>(p.kind);
  const auto m = mac8(std::span(out).first(kMacOffset), key);
  std::copy(m.begin(), m.end(), out.begin() + kMacOffset);
  return out;
}

std::optional<Probe> decode(std::span<const std::uint8_t> bytes, const Key& key) {
  if (bytes.size() != kSize || bytes[0] != kMagic || bytes[1] != kVersion) return std::nullopt;
  const auto expected = mac8(bytes.first(kMacOffset), key);
  // CRYPTO_memcmp takes the same time whether the first or the last byte differs, so an attacker
  // cannot learn the correct MAC byte by byte from response timing.
  if (CRYPTO_memcmp(expected.data(), bytes.data() + kMacOffset, kMacSize) != 0) return std::nullopt;
  const auto kind = bytes[kKindOffset];
  if (kind != static_cast<std::uint8_t>(Kind::Request) &&
      kind != static_cast<std::uint8_t>(Kind::Response))
    return std::nullopt;
  Probe p;
  p.kind = static_cast<Kind>(kind);
  std::copy_n(bytes.begin() + kTidOffset, p.tid.size(), p.tid.begin());
  return p;
}

}  // namespace probe
