#include "../aead.h"
#include <stddef.h>
#include <openssl/evp.h>
#include <string.h>

// #include <stdio.h>
#include <stdbool.h>
static size_t BLOCK_SIZE = (16*1024);

// bool set_block_size(size_t new_block_size) {
//   if (new_block_size % 64 != 0) {
//     return false;
//   } else {
//     BLOCK_SIZE = new_block_size;
//     return true;
//   }
// }

size_t aead_encrypt(const uint8_t * restrict in, uint8_t * restrict out, uint8_t * restrict mac, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    int len = 0;
    size_t ciphertext_len = 0;
    unsigned int tag_length;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *x = EVP_MD_CTX_create();

    EVP_DigestInit_ex(x, EVP_sha256(), NULL);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    
    size_t i = 0;
    for(; i + BLOCK_SIZE <= bytes; i += BLOCK_SIZE){
        EVP_EncryptUpdate(ctx,  &out[i], &len,  &in[i], BLOCK_SIZE);
        EVP_DigestUpdate(x, &in[i], BLOCK_SIZE);
        ciphertext_len += len;
    }
    // printf("i: %lu, bytes: %lu, block_size: %lu\n", i, bytes, BLOCK_SIZE);
    if (i < bytes) {
        const size_t rest = bytes - i;
        // printf("rest: %lu\n", rest);
        EVP_EncryptUpdate(ctx,  &out[i], &len,  &in[i], rest);
        EVP_DigestUpdate(x, &in[i], rest);
        ciphertext_len += len;
    }
    
    EVP_DigestFinal(x, mac, &tag_length);
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    ciphertext_len += len;

    EVP_MD_CTX_destroy(x);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + tag_length;
}



size_t aead_decrypt(const uint8_t * restrict in, const uint8_t * restrict mac, uint8_t * restrict out, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    int len = 0;
    size_t plaintext_len = 0;
    unsigned char tmp_hash[64];
    unsigned int tag_length;

    EVP_MD_CTX *x = EVP_MD_CTX_create();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DigestInit_ex(x, EVP_sha256(), NULL);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
 
    size_t i = 0;
    for(; i + BLOCK_SIZE <= bytes; i += BLOCK_SIZE){
        EVP_DecryptUpdate(ctx, &out[i], &len, &in[i], BLOCK_SIZE);
        plaintext_len += len;
        EVP_DigestUpdate(x, &out[i], BLOCK_SIZE);
    }
    // printf("i: %lu, bytes: %lu, block_size: %lu\n", i, bytes, BLOCK_SIZE);
    if (i < bytes) {
        const size_t rest = bytes - i;
        // printf("rest: %lu\n", rest);
        EVP_DecryptUpdate(ctx, &out[i], &len, &in[i], rest);
        plaintext_len += len;
        EVP_DigestUpdate(x, &out[i], rest);
    }

    EVP_DigestFinal(x, tmp_hash, &tag_length);
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    plaintext_len += len;

    EVP_MD_CTX_destroy(x);
    EVP_CIPHER_CTX_free(ctx);

    for(unsigned int i = 0; i < tag_length; i++){
        if(mac[i] != tmp_hash[i]){
            return 0;
        }
    }
    return plaintext_len;
}

