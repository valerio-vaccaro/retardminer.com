#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>

#include "blake2b.h"
#include "knots_pow.h"

namespace {
int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool decode_hex(const char *text, uint8_t *out, size_t bytes) {
  if (std::strlen(text) != bytes * 2) return false;
  for (size_t i = 0; i < bytes; ++i) {
    int hi = hex_nibble(text[2 * i]), lo = hex_nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = uint8_t((hi << 4) | lo);
  }
  return true;
}

void print_hex(const uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) std::printf("%02x", bytes[i]);
  std::puts("");
}
}  // namespace

int main(int argc, char **argv) {
  if (argc == 3 && !std::strcmp(argv[1], "hash")) {
    const size_t length = std::strlen(argv[2]) / 2;
    if (length > 256) return 2;
    uint8_t input[256], digest[32];
    if (!decode_hex(argv[2], input, length)) return 2;
    blake2b_256(input, length, digest);
    print_hex(digest, sizeof(digest));
    return 0;
  }
  if (argc == 3 && !std::strcmp(argv[1], "knots-v2")) {
    uint8_t header[164], digest[32];
    if (!decode_hex(argv[2], header, sizeof(header)) || !knots_blake2b_v2_pow(header, sizeof(header), digest)) return 2;
    print_hex(digest, sizeof(digest));
    return 0;
  }
  if (argc == 3 && !std::strcmp(argv[1], "bench")) {
    char *end = nullptr;
    const unsigned long count = std::strtoul(argv[2], &end, 10);
    if (!count || !end || *end) return 2;
    uint8_t header[80] = {}, digest[32];
    const auto start = std::chrono::steady_clock::now();
    for (unsigned long nonce = 0; nonce < count; ++nonce) {
      for (unsigned b = 0; b < 4; ++b) header[76 + b] = uint8_t(nonce >> (8 * b));
      blake2b_256(header, sizeof(header), digest);
    }
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    // Retain a digest byte so an optimizing compiler cannot discard the loop.
    std::printf("{\"hashes\":%lu,\"seconds\":%.9f,\"hashes_per_second\":%.3f,\"last_digest_byte\":%u}\n", count, seconds, count / seconds, digest[0]);
    return 0;
  }
  std::fprintf(stderr, "usage: %s hash HEX | knots-v2 HEADER_HEX | bench COUNT\n", argv[0]);
  return 2;
}
