#pragma once

#include <stddef.h>
#include <stdint.h>

// Unkeyed BLAKE2b with a 32-byte digest.
void blake2b_256(const uint8_t *input, size_t input_len, uint8_t output[32]);
