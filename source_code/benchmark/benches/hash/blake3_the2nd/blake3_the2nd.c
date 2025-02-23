#include "blake3.h"

//size_t hash(const uint8_t * __restrict__ in,  uint8_t * __restrict__ out, const size_t bytes)
size_t hash(const  unsigned char *in, unsigned char *out, const size_t bytes)
{
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  blake3_hasher_update(&hasher, in, bytes);

  blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
  return 32;
}
