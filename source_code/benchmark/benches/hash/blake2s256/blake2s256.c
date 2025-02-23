#include <stddef.h>
#include <openssl/evp.h>

size_t hash(const  unsigned char *in, unsigned char *out, const size_t bytes)
{
  int ok = 1;
  EVP_MD_CTX *x;
  unsigned int outlen;

  x = EVP_MD_CTX_create();
  if (!x) return 0;

  ok = EVP_DigestInit_ex(x,EVP_blake2s256(),NULL);
  ok = EVP_DigestUpdate(x,in,bytes);
  ok = EVP_DigestFinal(x,out,&outlen);

  EVP_MD_CTX_destroy(x);
  if (!ok) return 0;

  return 32;
}
