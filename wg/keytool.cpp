// pierce-wgkey: WireGuard keys, like `wg genkey` / `wg pubkey`, using BoringTun.
//   pierce-wgkey genkey              prints a new private key
//   pierce-wgkey pubkey < private    prints its public key
#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>

#include "wg/tunnel.hpp"

int main(int argc, char** argv) {
  const std::string_view cmd = argc == 2 ? argv[1] : "";
  if (cmd == "genkey") {
    std::cout << wg::generate_private_key() << "\n";
    return 0;
  }
  if (cmd == "pubkey") {
    std::string priv;
    std::getline(std::cin, priv);
    if (auto pub = wg::public_key(priv)) {
      std::cout << *pub << "\n";
      return 0;
    }
    std::fputs("pierce-wgkey: not a valid private key\n", stderr);
    return 1;
  }
  std::fputs("usage: pierce-wgkey genkey | pubkey < private\n", stderr);
  return 2;
}
