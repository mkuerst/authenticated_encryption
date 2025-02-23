// #include <iostream>
// using std::cout;
// using std::cerr;
// using std::endl;

#include <cryptopp/filters.h>
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cassert>
using namespace CryptoPP;

#include "../aead.hpp"

#define TAG_SIZE 16
#define KEY_LEN 32
#define IV_SIZE 16

// void printBytes(const byte* array, size_t size) {
//     for (size_t i = 0; i < size; ++i) {
//         std::cout << std::hex << static_cast<int>(array[i]) << " ";
//     }
//     std::cout << std::dec << std::endl;
// }

extern "C" size_t aead_encrypt(const uint8_t * __restrict__ in, uint8_t * __restrict__ out, uint8_t * __restrict__ mac, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes) {
    try
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, KEY_LEN, nonce, IV_SIZE);
        e.EncryptAndAuthenticate(out, mac, TAG_SIZE, nonce, IV_SIZE, nullptr, 0, in, bytes);
    }
    catch( CryptoPP::Exception& e )
    {
        // cerr << e.what() << endl;
        return 0;
    }

    return bytes+TAG_SIZE;
}


extern "C" size_t aead_decrypt(const uint8_t * __restrict__ in, const uint8_t * __restrict__ mac, uint8_t * __restrict__ out, const uint8_t * __restrict__ key, const uint8_t * __restrict__ nonce, const size_t bytes) {
    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, KEY_LEN, nonce, IV_SIZE);
        // AuthenticatedDecryptionFilter adf(d, nullptr, 0, TAG_SIZE);
        // adf.Put(in, bytes);
        // adf.Put(mac, TAG_SIZE);
        // adf.MessageEnd();
        // adf.Get(out, bytes);
        //d.DecryptAndVerify tries to cast the in buffer to a byte* ptr and throws an error -> Thus, using old Method with channels
        d.DecryptAndVerify((byte*) in, mac, TAG_SIZE, nonce, IV_SIZE, nullptr, 0, out, bytes);	

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        // if (adf.GetLastResult() == false) {
        //     std::cout << "Cryptopp_GCM decryption failed" << std::endl;
        //     return 0;
        // }
    }
    catch( CryptoPP::Exception& e )
    {
        // cerr << e.what() << endl;
        return 0;
    }
    return bytes;
}


// compile with: g++ -shared -o libcryptopp.so -O3 -fPIC cryptopp_gcm.cpp -lcryptopp