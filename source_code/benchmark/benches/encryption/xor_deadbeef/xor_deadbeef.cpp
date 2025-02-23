#include "../encryption.hpp"

#include <cstdio>

const uint64_t key = 0xDEADBEEFDEADBEEF;

size_t convert(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, const size_t bytes) {
  // printf("Encrypt xor_deadbeef: in: %p, out: %p, bytes: 0x%lx (0x%lx,
  // 0x%lx)\n", in, out, bytes, size_t(in) % sizeof(uint64_t), size_t(out) %
  // sizeof(uint64_t));
  if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0) {
    return 0;
  }
  const __restrict__ uint64_t *in_val = (uint64_t *)in;
  __restrict__ uint64_t *out_val = (uint64_t *)out;
  const int size = bytes / sizeof(uint64_t);
  for (size_t i = 0; i < size; i++) {
  // for (size_t i = 0; i * sizeof(uint64_t) < bytes; i++) {
    out_val[i] = in_val[i] ^ key;
  }
  return bytes;
}

extern "C" size_t encrypt(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, __restrict__ uint8_t *mac, const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce, const size_t bytes) {
  // Unused: mac, key, nonce
  return convert(in, out, bytes);
}

extern "C" size_t decrypt(const __restrict__ uint8_t *in, const __restrict__ uint8_t *mac, __restrict__ uint8_t *out, const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce, const size_t bytes) {
  // Unused: mac, key, nonce
  return convert(in, out, bytes);
}
