#pragma once

#include <stddef.h>
#include <stdint.h>

// Returns true when header is a complete Bitcoin Knots PR #359 v2 header.
bool is_knots_blake2b_v2_header(const uint8_t *header, size_t header_len);

// Calculates the proposed Bitcoin Knots BLAKE2b v2 proof-of-work hash.
// header must be the 164-byte on-wire header and output is 32 bytes.
bool knots_blake2b_v2_pow(const uint8_t *header, size_t header_len, uint8_t output[32]);
