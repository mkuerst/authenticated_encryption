#include "../hash.hpp"
#include "blake3.h"
#include <stdio.h>
#include <cstdlib>

extern "C" size_t hash(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, const size_t bytes) {
    // if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0 || bytes % 256 != 0) {
    //     return 0;
    // }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in, bytes);

    // size_t chunk_size = 2097152;
    // // Hash the data in chunks
    // size_t offset = 0;
    // while (offset < bytes) {
    //     size_t remaining_bytes = bytes - offset;
    //     size_t current_chunk_size = (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

    //     blake3_hasher_update(&hasher, in + offset, current_chunk_size);

    //     offset += current_chunk_size;
    // }

    blake3_hasher_finalize(&hasher, out, 32);

    return 32;
}

// create sahred library with: gcc -shared -o libblake3hash.so blake3hash.cpp blake3_misc/blake3.c blake3_misc/blake3_dispatch.c blake3_misc/blake3_portable.c blake3_misc/blake3_sse2_x86-64_unix.S blake3_misc/blake3_sse41_x86-64_unix.S blake3_misc/blake3_avx2_x86-64_unix.S blake3_misc/blake3_avx512_x86-64_unix.S
// link with: g++ -o blake3hash.o -c blake3hash.cpp -lblake3hash -L .
// execute with: LD_LIBRARY_PATH=. ./example_benchmark