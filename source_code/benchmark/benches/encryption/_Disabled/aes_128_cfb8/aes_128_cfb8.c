#include <stddef.h>
#include <openssl/evp.h>
#include "../encryption.h"

size_t encrypt(const uint8_t * restrict in, uint8_t * restrict out, uint8_t * restrict mac, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    (void) mac; // Unused
    
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key, iv);
    
    
    EVP_EncryptUpdate(ctx, out, &len, in, bytes);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

}


size_t decrypt(const uint8_t * restrict in, const uint8_t * restrict mac, uint8_t * restrict out, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    (void) mac; // Unused
    
    int len;
    int plaintext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

   
    
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key, iv);
    
    
    EVP_DecryptUpdate(ctx, out, &len, in, bytes);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
