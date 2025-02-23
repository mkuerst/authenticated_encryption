#include "../hash.hpp"
#include "merkletree_par.hpp"

#define BLOCK_SIZE 4096 // Needs to be a multiple of 2 and a divisor of bytes (for now)

extern "C" size_t hash(const __restrict__ uint8_t *in,
                       __restrict__ uint8_t *out, const size_t bytes)
{
    if (size_t(in) % sizeof(uint64_t) != 0 || size_t(out) % sizeof(uint64_t) != 0 || bytes % BLOCK_SIZE != 0)
    {
        return 0;
    }

    MerkleNode *tree = buildTree(in, out, bytes, BLOCK_SIZE);

    destroyTree(tree);

    return 4 * sizeof(uint64_t);
}