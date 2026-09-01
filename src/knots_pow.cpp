#include "knots_pow.h"

#include <string.h>

#include "blake2b.h"

namespace {
constexpr size_t HEADER_V2_SIZE = 164;

inline uint32_t rotr32(uint32_t value, unsigned bits) {
  return (value >> bits) | (value << (32 - bits));
}

class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() {
    state_[0] = 0x6a09e667U; state_[1] = 0xbb67ae85U;
    state_[2] = 0x3c6ef372U; state_[3] = 0xa54ff53aU;
    state_[4] = 0x510e527fU; state_[5] = 0x9b05688cU;
    state_[6] = 0x1f83d9abU; state_[7] = 0x5be0cd19U;
    bytes_ = 0; used_ = 0;
  }

  void write(const uint8_t *data, size_t length) {
    bytes_ += length;
    while (length) {
      const size_t take = length < (64 - used_) ? length : (64 - used_);
      memcpy(block_ + used_, data, take);
      used_ += take; data += take; length -= take;
      if (used_ == 64) { compress(block_); used_ = 0; }
    }
  }

  void finish(uint8_t output[32]) {
    const uint64_t bits = bytes_ * 8;
    block_[used_++] = 0x80;
    if (used_ > 56) {
      while (used_ < 64) block_[used_++] = 0;
      compress(block_); used_ = 0;
    }
    while (used_ < 56) block_[used_++] = 0;
    for (unsigned i = 0; i < 8; ++i) block_[used_++] = uint8_t(bits >> (56 - 8 * i));
    compress(block_);
    for (unsigned i = 0; i < 8; ++i) {
      output[4 * i] = uint8_t(state_[i] >> 24);
      output[4 * i + 1] = uint8_t(state_[i] >> 16);
      output[4 * i + 2] = uint8_t(state_[i] >> 8);
      output[4 * i + 3] = uint8_t(state_[i]);
    }
  }

 private:
  void compress(const uint8_t block[64]) {
    static constexpr uint32_t K[64] = {
      0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
      0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
      0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
      0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
      0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
      0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
      0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
      0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i) w[i] = (uint32_t(block[4*i]) << 24) | (uint32_t(block[4*i+1]) << 16) | (uint32_t(block[4*i+2]) << 8) | block[4*i+3];
    for (unsigned i = 16; i < 64; ++i) w[i] = (rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3)) + w[i-16] + (rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10)) + w[i-7];
    uint32_t a=state_[0], b=state_[1], c=state_[2], d=state_[3], e=state_[4], f=state_[5], g=state_[6], h=state_[7];
    for (unsigned i = 0; i < 64; ++i) {
      const uint32_t t1 = h + (rotr32(e,6)^rotr32(e,11)^rotr32(e,25)) + ((e&f)^((~e)&g)) + K[i] + w[i];
      const uint32_t t2 = (rotr32(a,2)^rotr32(a,13)^rotr32(a,22)) + ((a&b)^(a&c)^(b&c));
      h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d; state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
  }
  uint32_t state_[8]; uint8_t block_[64]; uint64_t bytes_; size_t used_;
};

void sha256(const uint8_t *data, size_t length, uint8_t output[32]) {
  Sha256 hash; hash.write(data, length); hash.finish(output);
}

void tagged_hash(const char *tag, const uint8_t *data, size_t length, uint8_t output[32]) {
  uint8_t tag_hash[32]; sha256(reinterpret_cast<const uint8_t *>(tag), strlen(tag), tag_hash);
  Sha256 hash; hash.write(tag_hash, sizeof(tag_hash)); hash.write(tag_hash, sizeof(tag_hash)); hash.write(data, length); hash.finish(output);
}

void append(uint8_t *out, size_t &at, const uint8_t *data, size_t length) { memcpy(out + at, data, length); at += length; }
} // namespace

bool is_knots_blake2b_v2_header(const uint8_t *header, size_t header_len) {
  return header_len == HEADER_V2_SIZE && (header[3] & 0x80U);
}

bool knots_blake2b_v2_pow(const uint8_t *header, size_t header_len, uint8_t output[32]) {
  if (!is_knots_blake2b_v2_header(header, header_len)) return false;
  uint8_t work[192], h1[32], h2[32], hash1[32], hash2[32], mask[32] = {};
  size_t at = 0;
  uint8_t version[4] = {header[0], header[1], header[2], uint8_t(header[3] & 0x7fU)};
  append(work, at, version, 4);
  for (unsigned i = 0; i < 32; ++i) work[at + i] = header[4 + 31 - i];
  at += 32;
  append(work, at, header + 128, 4); append(work, at, header + 36, 32); append(work, at, header + 68, 4);
  const uint8_t zero4[4] = {}; const uint8_t zero1[1] = {}; append(work, at, zero1, 1); append(work, at, header + 72, 4); append(work, at, header + 108, 2); append(work, at, zero4, 2);
  append(work, at, header + 110, 2);
  uint8_t xor_key_hash[32]; tagged_hash("Bitcoin block hash PoW XOR key", header + 112, 16, xor_key_hash); append(work, at, xor_key_hash, 32);
  tagged_hash("Bitcoin block header 1", work, at, h1);

  at = 0; append(work, at, h1, 32); const uint8_t zero32[32] = {}; append(work, at, zero32, 32); append(work, at, header + 132, 32);
  tagged_hash("Merge-mining hook", work, at, h2);

  at = 0; append(work, at, zero4, 4); append(work, at, h2, 32); append(work, at, header + 88, 16); blake2b_256(work, at, hash1);

  at = 0;
  const uint8_t profile = header[110] & 3U;
  if (profile == 0 || profile == 2 || profile == 3) {
    const size_t zeros = profile == 2 ? 48 : (profile == 3 ? 80 : 0);
    memset(work, 0, zeros); at = zeros;
    if (profile == 0) {
      uint8_t previous[32];
      for (unsigned i = 0; i < 32; ++i) previous[i] = header[4 + 31 - i];
      tagged_hash("Bitcoin prevblock header, hashed", previous, sizeof(previous), work + at);
      memset(work + at, 0, 6); at += 32;
    } else append(work, at, h2, 32);
    append(work, at, header + 76, 4); append(work, at, header + 80, 4); append(work, at, header + 104, 4); append(work, at, header + 84, 4); append(work, at, hash1, 32);
  } else {
    append(work, at, header + 76, 4); append(work, at, header + 80, 4); append(work, at, header + 84, 4); append(work, at, header + 104, 4); append(work, at, hash1, 32); append(work, at, h2, 32);
  }
  blake2b_256(work, at, hash2);
  bool has_key = false; for (unsigned i = 0; i < 16; ++i) has_key |= header[112 + i] != 0;
  if (has_key) {
    tagged_hash("Bitcoin block hash PoW XOR mask", header + 112, 16, mask);
    const unsigned clear = header[111];
    memset(mask, 0, clear / 8);
    if (clear / 8 < 32) mask[clear / 8] &= uint8_t(0xffU >> (clear % 8));
  }
  for (unsigned i = 0; i < 32; ++i) output[i] = hash2[i] ^ mask[i];
  return true;
}
