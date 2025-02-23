#include "../encryption.hpp"
#include "chacha20.h"
#include <cstdio>
#include <cstdlib>
#include <immintrin.h>

size_t run(const __restrict__ uint8_t *in, __restrict__ uint8_t *out,
           const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce,
           const size_t bytes) {
  uint8_t *state = (uint8_t *)_mm_malloc(ChaCha20StateSizeBytes, 32);
  ChaCha20SetCtr(state, (uint8_t *)"\0\0\0\0");
  ChaCha20SetKey(state, key);
  ChaCha20SetNonce(state, nonce);
  ChaCha20EncryptBytes(state, in, out, bytes);
  free(state);
  return bytes;
}

extern "C" size_t encrypt(const uint8_t *__restrict__ in,
                          uint8_t *__restrict__ out, uint8_t *__restrict__ mac,
                          const uint8_t *__restrict__ key,
                          const uint8_t *__restrict__ nonce,
                          const size_t bytes) {
  return run(in, out, key, nonce, bytes);
}

extern "C" size_t
decrypt(const __restrict__ uint8_t *in, const __restrict__ uint8_t *mac,
        __restrict__ uint8_t *out, const __restrict__ uint8_t *key,
        const __restrict__ uint8_t *nonce, const size_t bytes) {
  return run(in, out, key, nonce, bytes);
}
