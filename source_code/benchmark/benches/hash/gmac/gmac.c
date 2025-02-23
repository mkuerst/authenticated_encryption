#include <stddef.h>
#include <openssl/evp.h>
#include <string.h>

size_t hash(const  unsigned char *in, unsigned char *out, const size_t bytes)
{
  
  unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
                        };

    EVP_CIPHER_CTX *ctx;
    int len;
    //size_t ciphertext_len = 0;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    /* Initialise the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    
    EVP_EncryptInit_ex(ctx, NULL, NULL, iv, NULL);
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
   
    EVP_EncryptUpdate(ctx, NULL, &len, in, bytes);
    
    EVP_EncryptFinal_ex(ctx, NULL, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out);
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);


    return 16;
}