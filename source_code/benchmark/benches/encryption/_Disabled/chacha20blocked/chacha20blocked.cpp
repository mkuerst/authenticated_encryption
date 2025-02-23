#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"
#include "../encryption.hpp"
#include <algorithm>

static size_t BLOCK_SIZE = (2*1024*1024);

extern "C" bool set_block_size(size_t new_block_size) {
  if (new_block_size % 64 != 0) {
    return false;
  } else {
    BLOCK_SIZE = new_block_size;
    return true;
  }
}

size_t run(const __restrict__ uint8_t *in, __restrict__ uint8_t *out,
           const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce,
           const size_t bytes) {
  uint32_t count = 0x00000000;

  ChaCha20_Ctx ctx;
  ChaCha20_init(&ctx, key, nonce, count);

// No real difference between 16*1024, 2*1024*1024 and 32*1024*1024
// Approx. 4.9% slower with 1024
// #define BLOCK_SIZE (2*1024*1024)
  const size_t blocks = bytes / BLOCK_SIZE;
  const size_t rest = bytes % BLOCK_SIZE;

  for (size_t i = 0; i < blocks; i++) {
    const size_t offset = i * BLOCK_SIZE;
    std::copy_n(in + offset, BLOCK_SIZE, out + offset);
    ChaCha20_xor(&ctx, out + offset, BLOCK_SIZE);
  }
  if (rest != 0) {
    const size_t offset = bytes - rest;
    std::copy_n(in + offset, rest, out + offset);
    ChaCha20_xor(&ctx, out + offset, rest);
  }
  // The array 'data' is now encrypted (or decrypted if it
  // was already encrypted)

  return bytes;
}

extern "C" size_t encrypt(const __restrict__ uint8_t *in,
                          __restrict__ uint8_t *out, __restrict__ uint8_t *mac,
                          const __restrict__ uint8_t *key,
                          const __restrict__ uint8_t *nonce,
                          const size_t bytes) {
  return run(in, out, key, nonce, bytes);
}

extern "C" size_t
decrypt(const __restrict__ uint8_t *in, const __restrict__ uint8_t *mac,
        __restrict__ uint8_t *out, const __restrict__ uint8_t *key,
        const __restrict__ uint8_t *nonce, const size_t bytes) {
  return run(in, out, key, nonce, bytes);
}
