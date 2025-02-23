#include "../aead.h"
#include <stddef.h>
#include <openssl/evp.h>
#include <string.h>


size_t aead_encrypt(const uint8_t * restrict in, uint8_t * restrict out, uint8_t * restrict mac, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    size_t ciphertext_len = 0;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    /* Initialise the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 32, NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    //EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    EVP_EncryptUpdate(ctx, out, &len, in, bytes);
    ciphertext_len = len;
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    ciphertext_len += len;
    /* Get the tag */
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mac);
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len + 16;
}


size_t aead_decrypt(const uint8_t * restrict in, const uint8_t * restrict mac, uint8_t * restrict out, const uint8_t * restrict key, const uint8_t * restrict iv, const size_t bytes)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    size_t plaintext_len = 0;
    int ret = 1;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    /* Initialise the decryption operation. */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 32, NULL);

    /* Initialise key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    //if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
     //   handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    EVP_DecryptUpdate(ctx, out, &len, in, bytes);
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, &mac);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, mac);

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, out + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return 0;
    }
}

