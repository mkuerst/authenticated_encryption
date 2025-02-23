#ifndef MERKLE_TREE_PAR_H
#define MERKLE_TREE_PAR_H

extern "C"
{

#include <cstddef>
#include <cstdint>

    struct MerkleNode
    {
        uint64_t *hash;
        MerkleNode *left;
        MerkleNode *right;
    };

    MerkleNode *buildTree(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, size_t data_size, size_t block_size);
    void destroyTree(MerkleNode *node);

    MerkleNode *createLeafNode(const __restrict__ uint64_t *data, size_t block_size);
    MerkleNode *createInternalNode(MerkleNode *left, MerkleNode *right, size_t block_size);

    size_t xor256(const __restrict__ uint64_t *in_xor, __restrict__ uint64_t *out_xor, const size_t bytes);
}

#endif // MERKLE_TREE_H
