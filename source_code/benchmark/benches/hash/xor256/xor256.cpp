#include "../hash.hpp"

extern "C" size_t hash(const __restrict__ uint8_t *in,
                       __restrict__ uint8_t *out, const size_t bytes) {
  if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0) {
    return 0;
  }
  const uint64_t *in_val = (uint64_t *)in;
  uint64_t acc[4] = {0};
  const size_t steps = bytes / (sizeof(uint64_t));
  size_t i = 0;
  for (; i < steps; i += 4) {
    for (size_t j = 0; j < 4; j++) {
      acc[j] ^= in_val[i + j];
    }
  }
  
  const size_t checked_bytes = steps * sizeof(uint64_t);
  for (size_t i = checked_bytes; i < bytes; i++) {
    uint8_t *acc_u8 = (uint8_t *)acc;
    acc_u8[i % (sizeof(uint64_t) * 4)] ^= in[i];
  }
  uint64_t *out_val = (uint64_t *)out;
  for (size_t j = 0; j < 4; j++) {
    out_val[j] = acc[j];
  }
  return 4 * sizeof(uint64_t);
}
