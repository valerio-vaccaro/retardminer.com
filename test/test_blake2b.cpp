#include <Arduino.h>
#include <unity.h>

#include "blake2b.h"
#include "knots_pow.h"

namespace {
void assert_hex(const uint8_t *actual, const char *expected) {
  const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < 32; ++i) {
    TEST_ASSERT_EQUAL_UINT8(digits[actual[i] >> 4], expected[2 * i]);
    TEST_ASSERT_EQUAL_UINT8(digits[actual[i] & 15], expected[2 * i + 1]);
  }
}

uint8_t nibble(char c) { return c <= '9' ? uint8_t(c - '0') : uint8_t(c - 'a' + 10); }
void decode_hex(const char *text, uint8_t *out, size_t length) {
  for (size_t i = 0; i < length; ++i) out[i] = uint8_t((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
}
} // namespace

void test_rfc7693_blake2b_256_abc() {
  uint8_t hash[32];
  blake2b_256(reinterpret_cast<const uint8_t *>("abc"), 3, hash);
  assert_hex(hash, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

void test_bitcoin_header_hashed_with_blake2b() {
  // Serialized Bitcoin genesis header: version, previous block hash, merkle
  // root, nTime, nBits, nonce. Only SHA-256d is replaced by BLAKE2b-256.
  const uint8_t header[80] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,
    0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,
    0x4b,0x1e,0x5e,0x4a,0x29,0xab,0x5f,0x49,0xff,0xff,0x00,0x1d,0x1d,0xac,0x2b,0x7c};
  uint8_t hash[32];
  blake2b_256(header, sizeof(header), hash);

  TEST_ASSERT_EQUAL_HEX8(0x1d, header[76]);
  TEST_ASSERT_EQUAL_HEX8(0x7c, header[79]);
  assert_hex(hash, "963bb8ec007120171e983206e8a55d5a85d40b9d43f1dee026ad1d6121fbad54");
}

void test_knots_v2_profile_zero_vector() {
  // Official Bitcoin Knots PR #359 header-v2 vector, profile 0.
  const char *hex = "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
                    "0302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003005c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";
  uint8_t header[164], hash[32]; decode_hex(hex, header, sizeof(header));
  TEST_ASSERT_TRUE(knots_blake2b_v2_pow(header, sizeof(header), hash));
  assert_hex(hash, "c80e70f7a4a0dbfef4b23c32c52a8e632115c7056b85efd495eadaf66bbc0aef");
}

void setup() {
  delay(1000);
  UNITY_BEGIN();
  RUN_TEST(test_rfc7693_blake2b_256_abc);
  RUN_TEST(test_bitcoin_header_hashed_with_blake2b);
  RUN_TEST(test_knots_v2_profile_zero_vector);
  UNITY_END();
}

void loop() {}
