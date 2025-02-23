#include <cstddef>
#include <cstdint>

// # Return value:
// 0 on failure
// number of bytes written to out + mac on success
extern "C" size_t encrypt(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, __restrict__ uint8_t *mac, const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce, const size_t bytes);

// # Return value:
// 0 on failure
// number of bytes written to out on success
extern "C" size_t decrypt(const __restrict__ uint8_t *in, const __restrict__ uint8_t *mac, __restrict__ uint8_t *out, const __restrict__ uint8_t *key, const __restrict__ uint8_t *nonce, const size_t bytes);
