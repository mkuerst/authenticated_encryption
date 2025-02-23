#include <cryptopp/cryptlib.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include "../hash.hpp"

using namespace CryptoPP;



extern "C" size_t hash(const __restrict__ uint8_t *in, __restrict__ uint8_t *out, const size_t bytes) {
    // AutoSeededRandomPool prng;
    // byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    // byte iv[CryptoPP::AES::BLOCKSIZE];
    // GCM<AES>::Encryption ghash;

    // prng.GenerateBlock(key, sizeof(key));
    // prng.GenerateBlock(iv, sizeof(iv));

    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];
    GCM<AES>::Encryption ghash;
    
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = i % 256;
    }
    for (size_t i = 0; i < sizeof(iv); i++) {
        iv[i] = i % 256;
    }

    ghash.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
    ghash.Update(in, bytes);
    ghash.Final(out);

    return 16;
}
