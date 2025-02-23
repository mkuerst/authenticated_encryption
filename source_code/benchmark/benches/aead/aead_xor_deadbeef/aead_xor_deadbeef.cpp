#include "../aead.hpp"

// #include <iostream>

// const uint64_t key = 0xDEADBEEFDEADBEEF;

extern "C" size_t aead_encrypt(const uint8_t * __restrict__ in, uint8_t * __restrict__ out, uint8_t * __restrict__ mac, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes) {
    if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0 || size_t(mac) % sizeof(uint64_t) != 0 || size_t(key) % sizeof(uint64_t) != 0 || size_t(nonce) % sizeof(uint64_t) != 0) {
        return 0;
    }
    const uint64_t key_value = *((uint64_t *)key);
    uint64_t *nonce_u64 = (uint64_t *) nonce;
    uint64_t check_sum[2] = {nonce_u64[0], nonce_u64[1]};

    const uint64_t * __restrict__ in_val = (uint64_t * __restrict__)in;
    uint64_t * __restrict__ out_val = (uint64_t * __restrict__)out;
    const uint64_t size = (uint64_t)bytes / sizeof(uint64_t);
    for (uint64_t i = 0; i < size; i++) {
        const uint64_t next = in_val[i];
        check_sum[i % 2] ^= next;
        // check_sum[0] ^= next;
        out_val[i] = next ^ key_value;
    }

    const size_t checked_bytes = size * sizeof(uint64_t);
    for (size_t i = checked_bytes; i < bytes; i++) {
        uint8_t *check_sum_u8 = (uint8_t *)check_sum;
        check_sum_u8[i % (sizeof(check_sum))] ^= in[i];
    }

    uint64_t * __restrict__ mac_val = (uint64_t * __restrict__)mac;
    mac_val[0] = check_sum[0];
    mac_val[1] = check_sum[1];
    return bytes + 2 * sizeof(uint64_t);
}

extern "C" size_t aead_decrypt(const uint8_t * __restrict__ in, const uint8_t * __restrict__ mac, uint8_t * __restrict__ out, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes) {
    if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0 || size_t(mac) % sizeof(uint64_t) != 0 || size_t(key) % sizeof(uint64_t) != 0 || size_t(nonce) % sizeof(uint64_t) != 0) {
        // std::cout << "size_t(in) % sizeof(uint64_t) == " << size_t(in) << " % " << sizeof(uint64_t) << std::endl;
        // std::cout << "size_t(out) % sizeof(uint64_t) == " << size_t(out) << " % " << sizeof(uint64_t) << std::endl;
        // std::cout << "size_t(key) % sizeof(uint64_t) == " << size_t(mac) << " % " << sizeof(uint64_t) << std::endl;
        // std::cout << "size_t(key) % sizeof(uint64_t) == " << size_t(key) << " % " << sizeof(uint64_t) << std::endl;
        // std::cout << "size_t(nonce) % sizeof(uint64_t) == " << size_t(nonce) << " % " << sizeof(uint64_t) << std::endl;
        return 0;
    }
    const uint64_t key_value = *((uint64_t *)key);
    uint64_t *nonce_u64 = (uint64_t *) nonce;
    uint64_t check_sum[2] = {nonce_u64[0], nonce_u64[1]};

    const uint64_t * __restrict__ in_val = (uint64_t * __restrict__)in;
    uint64_t * __restrict__ out_val = (uint64_t * __restrict__)out;
    const uint64_t size = (uint64_t)bytes / sizeof(uint64_t);
    for (uint64_t i = 0; i < size; i++) {
        const uint64_t decrypted = in_val[i] ^ key_value;
        check_sum[i % 2] ^= decrypted;
        // check_sum[0] ^= decrypted;
        out_val[i] = decrypted;
    }

    const size_t checked_bytes = size * sizeof(uint64_t);
    for (size_t i = checked_bytes; i < bytes; i++) {
        uint8_t *check_sum_u8 = (uint8_t *)check_sum;
        check_sum_u8[i % (sizeof(check_sum))] ^= in[i];
    }

    uint64_t * __restrict__ mac_val = (uint64_t * __restrict__)mac;
    if (check_sum[0] != mac_val[0] || check_sum[1] != mac_val[1]) {
        return 0;
    }
    return bytes;
}
