#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"
#include "../encryption.hpp"
#include <algorithm>

size_t run(const __restrict__ uint8_t *in, __restrict__ uint8_t *out,
           const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce,
           const size_t bytes) {
  uint32_t count = 0x00000000;

  ChaCha20_Ctx ctx;
  ChaCha20_init(&ctx, key, nonce, count);

  std::copy_n(in, bytes, out);
  ChaCha20_xor(&ctx, out, bytes);
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
