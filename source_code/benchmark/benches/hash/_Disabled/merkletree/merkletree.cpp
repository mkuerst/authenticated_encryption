#include "merkletree.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>

#define HASH_SIZE 4 * sizeof(uint64_t) // 256 bits or 32 bytes for xor256

MerkleNode *createLeafNode(const __restrict__ uint64_t *data, size_t block_size)
{
    MerkleNode *node = (MerkleNode *)malloc(sizeof(MerkleNode));
    node->hash = (uint64_t *)malloc(4 * sizeof(uint64_t));
    size_t bytes = xor256(data, node->hash, block_size);
    node->left = NULL;
    node->right = NULL;
    return node;
}

MerkleNode *createInternalNode(MerkleNode *left, MerkleNode *right, size_t block_size)
{
    MerkleNode *node = (MerkleNode *)malloc(sizeof(MerkleNode));
    node->hash = (uint64_t *)malloc(HASH_SIZE);
    uint64_t *in = (uint64_t *)malloc(2 * HASH_SIZE);

    for (int i = 0; i < 4; i++)
    {
        in[i] = left->hash[i];
        in[i + 4] = right->hash[i];
    }

    size_t bytes = xor256(in, node->hash, 2 * HASH_SIZE);
    node->left = left;
    node->right = right;
    free(in);
    return node;
}

void destroyTree(MerkleNode *node)
{
    if (node != NULL)
    {
        destroyTree(node->left);
        destroyTree(node->right);
        free(node->hash);
        free(node);
    }
}

MerkleNode *buildTree(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, size_t data_size, size_t block_size)
{
    if (data_size == 0 || block_size == 0 || data_size % block_size != 0)
    {
        return NULL;
    }

    size_t blocks = data_size / block_size;

    MerkleNode **nodes = (MerkleNode **)malloc(blocks * sizeof(MerkleNode *));

    const uint64_t *data = (uint64_t *)in;

    for (size_t i = 0; i < blocks; ++i)
    {
        nodes[i] = createLeafNode(&data[i * block_size / sizeof(uint64_t)], block_size);
    }

    while (blocks > 1)
    {
        size_t new_blocks = (blocks + 1) / 2;
        MerkleNode **new_nodes = (MerkleNode **)malloc(new_blocks * sizeof(MerkleNode *));

        for (size_t i = 0; i < blocks; i += 2)
        {
            MerkleNode *left = nodes[i];
            MerkleNode *right = nodes[i + 1];
            new_nodes[i / 2] = createInternalNode(left, right, block_size);
        }

        free(nodes);
        nodes = new_nodes;
        blocks = new_blocks;
    }

    MerkleNode *root = nodes[0];

    uint64_t *out_val = (uint64_t *)out;
    for (size_t j = 0; j < HASH_SIZE; j++)
    {
        out_val[j] = root->hash[j];
    }

    free(nodes);

    return root;
}

size_t xor256(const __restrict__ uint64_t *in_xor,
              __restrict__ uint64_t *out_xor, const size_t bytes)
{
    if (size_t(in_xor) % sizeof(uint64_t) != 0 ||
        size_t(out_xor) % sizeof(uint64_t) != 0)
    {
        return 0;
    }

    uint64_t acc[4] = {0};
    const size_t steps = bytes / (sizeof(uint64_t));
    size_t i = 0;
    for (; i < steps; i += 4)
    {
        for (size_t j = 0; j < 4; j++)
        {
            acc[j] ^= in_xor[i + j];
        }
    }

    for (size_t j = 0; j < 4; j++)
    {
        out_xor[j] = acc[j];
    }
    return 32;
}

size_t sha256(const unsigned char *in, unsigned char *out, const size_t bytes)
{
    int ok = 1;
    EVP_MD_CTX *x;
    unsigned int outlen;

    x = EVP_MD_CTX_create();
    if (!x)
        return 0;

    ok = EVP_DigestInit_ex(x, EVP_sha256(), NULL);
    ok = EVP_DigestUpdate(x, in, bytes);
    ok = EVP_DigestFinal(x, out, &outlen);

    EVP_MD_CTX_destroy(x);
    if (!ok)
        return 0;

    return 32;
}