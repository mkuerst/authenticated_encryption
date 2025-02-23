#include "blake3.h"
//#include <errno.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>



size_t hash(const uint8_t * __restrict__ in,  uint8_t * __restrict__ out, const size_t bytes){
  // Initialize the hasher.
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  blake3_hasher_update(&hasher, in, bytes);

  blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);

  return 32;
}


size_t hash_looped(const uint8_t * __restrict__ in,  uint8_t * __restrict__ out, const size_t bytes){
  // Initialize the hasher.
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  for(int i=0; i<bytes; i+=64){
    blake3_hasher_update(&hasher, &in[i], 64);
  }

  blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);

  return 32;
}


int main(void) {
  
  unsigned char *plaintext = (unsigned char *) "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The ";
  int len_plain = 10;//strlen ((char *)plaintext);


  uint8_t output[BLAKE3_OUT_LEN];

  hash(plaintext, output, len_plain);


  // Print the hash as hexadecimal.
  /*for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
    printf("%02x", output[i]);
  }
  printf("\n");*/
  return 0;
}


