#include <cstddef>
#include <cstdint>

extern "C" size_t hash(const __restrict__ uint8_t *in,
                       __restrict__ uint8_t *out, const size_t bytes);
