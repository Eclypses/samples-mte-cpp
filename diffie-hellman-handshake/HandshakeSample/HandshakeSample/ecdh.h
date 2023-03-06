#ifndef ECDH_H
#define ECDH_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C"
{
#endif
  // Returns the ECDH shared secret
  // Given the peer's public key string, the key_info, and the kctx
  // The returned buffer needs to be freed from the heap
  char* createSharedSecret(char* peer_public_key, EVP_PKEY* key_info, EVP_PKEY_CTX* kctx);

  // Creates the public key within key_info
  // Given the kctx and key_info
  // Returns this device's public key
  // The returned buffer needs to be freed from the heap
  char* getPublicKey(EVP_PKEY_CTX** kctx, EVP_PKEY** key_info);

#ifdef __cplusplus
}
#endif

#endif