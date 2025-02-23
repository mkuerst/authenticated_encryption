#include <cstddef>
#include <cstdint>

// # Return value:
// 0 on failure
// number of bytes written to out + mac on success
extern "C" size_t aead_encrypt(const uint8_t * __restrict__ in, uint8_t * __restrict__ out, uint8_t * __restrict__ mac, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes);

// # Return value:
// 0 on failure
// number of bytes written to out on success
extern "C" size_t aead_decrypt(const uint8_t * __restrict__ in, const uint8_t * __restrict__ mac, uint8_t * __restrict__ out, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes);
