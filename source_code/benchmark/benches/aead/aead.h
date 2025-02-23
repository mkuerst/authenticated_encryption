#include <stddef.h>
#include <stdint.h>

// # Return value:
// 0 on failure
// number of bytes written to out + mac on success
size_t aead_encrypt(const uint8_t * restrict in, uint8_t * restrict out, uint8_t * restrict mac, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes);

// # Return value:
// 0 on failure
// number of bytes written to out on success
size_t aead_decrypt(const uint8_t * restrict in, const uint8_t * restrict mac, uint8_t * restrict out, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes);
