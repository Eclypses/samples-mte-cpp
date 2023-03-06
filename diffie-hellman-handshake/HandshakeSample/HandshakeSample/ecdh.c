#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

/* PEM File Format:

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUWfMuMPzVYDus4SdOSfY7yk+DThg
omkm98ZQ02/sjClkcwHVu2MYsZSpkx0aIVJSthcsyMmsJmK/0ohWb5YhVQ==
-----END PUBLIC KEY-----

*/

// Returns the SHA-256 hash of "ecdh_shared_secret", which is of length "secret_len"
// Given the ECDH shared secret and its length
// The returned buffer needs to be freed from the heap
static unsigned char* sha256Key(unsigned char* ecdh_shared_secret, size_t secret_len)
{
    // allocate space for the hashed result
    unsigned char* hashed_buffer = malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    if (hashed_buffer == NULL)
    {
        fprintf(stderr, "Error with malloc(): NULL\n");
        return NULL;
    }

    // create a sha256 context
    SHA256_CTX sha256;

    // initialize the sha256 context
    SHA256_Init(&sha256);

    // update the sha256 context using the ECDH shared secret and its length
    SHA256_Update(&sha256, ecdh_shared_secret, secret_len);

    // finalize the sha256 hashing, and store the result in hashed_buffer
    SHA256_Final(hashed_buffer, &sha256);

    // return the SHA-256 hashed buffer
    return hashed_buffer;
}

// Returns a Base64 encoded string
// Given a buffer and its length
// The returned buffer needs to be freed from the heap
static char* base64Encode(unsigned char* sha256_key, size_t secret_len)
{
    BIO* bio;
    BIO* b64;
    FILE* stream;

    // calculate the size of the Base64 encoded result
    int encoded_size = 4 * ceil((double)secret_len / 3);

    // allocate a buffer to hold the Base64 encoded result
    char* base64_result = malloc((encoded_size + 1) * sizeof(char));

    // open a file stream to write to
    stream = fmemopen(base64_result, encoded_size + 1, "w");

    // create a new BIO for Base64 encoding
    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
    {
        fprintf(stderr, "Error with BIO_new(): NULL\n");
        return NULL;
    }

    // create a new BIO using the file stream
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    if (bio == NULL)
    {
        fprintf(stderr, "Error with BIO_new_fp(): NULL\n");
        return NULL;
    }

    // push b64 onto bio
    bio = BIO_push(b64, bio);

    // set the BIO flags to ignore newline characters
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // write the Base64 encoded buffer to the bio
    BIO_write(bio, sha256_key, secret_len);

    // flush the BIO
    BIO_flush(bio);

    // free BIOs
    BIO_free_all(bio);

    // close the file stream
    fclose(stream);

    // return the Base64 encoded string
    return base64_result;
}

// Returns the full contents of the PEM file
// Given the key_info
static char* getFullPem(EVP_PKEY* key_info)
{
    char* bio_data;

    // create a new BIO to hold the public key
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        fprintf(stderr, "Error with BIO_new(): NULL\n");
        return NULL;
    }

    // write the PEM public key to the BIO
    PEM_write_bio_PUBKEY(bio, key_info);

    // populate the bio_data buffer with the PEM public key
    BIO_get_mem_data(bio, &bio_data);

    // free the BIO
    //BIO_free_all(bio);

    // return the PEM formatted public key string
    return bio_data;
}

// Returns only the contents of the PEM file
// Strips out the header, footer, and newlines
// Given the key_info
// The returned buffer needs to be freed from the heap
static char* getPemKey(EVP_PKEY* key_info)
{
    // obtain the full PEM public key (with headers)
    char* full_pem = getFullPem(key_info);

    // extract the first line of the PEM file
    char* token = strtok(full_pem, "\n");

    // extract the second line of the PEM file
    token = strtok(NULL, "\n");

    // get the size of this line
    int line1_size = strlen(token) + 1;

    // allocate a new buffer to hold the first line of the public key
    char* line1 = malloc(line1_size * sizeof(char));
    if (line1 == NULL)
    {
        fprintf(stderr, "Error with malloc(): NULL\n");
        return NULL;
    }

    // copy the first line of the public key into the buffer
    strcpy(line1, token);

    // extract the third line of the PEM file
    token = strtok(NULL, "\n");

    // get the size of this line
    int line2_size = strlen(token) + 1;

    // allocate a new buffer to hold the second line of the public key
    char* line2 = malloc(line2_size * sizeof(char));
    if (line2 == NULL)
    {
        fprintf(stderr, "Error with malloc(): NULL\n");
        return NULL;
    }

    // copy the second line of the public key into the buffer
    strcpy(line2, token);

    // allocate a new buffer to hold both lines of the public key
    char* public_key = malloc((line1_size + line2_size - 1) * sizeof(char));
    if (public_key == NULL)
    {
        fprintf(stderr, "Error with malloc(): NULL\n");
        return NULL;
    }

    // copy the first line of the public key into the buffer
    strcpy(public_key, line1);

    // copy the second line of the public key into the buffer
    strcpy(public_key + line1_size - 1, line2);

    // free the buffers that are done
    free(line1);
    free(line2);

    // return the public key string
    return public_key;
}

// Returns the ECDH shared secret
// Given the peer's public key string, the key_info, and the kctx
// The returned buffer needs to be freed from the heap
char* createSharedSecret(char* peer_public_key, EVP_PKEY* key_info, EVP_PKEY_CTX* kctx)
{
    EVP_PKEY* peer_key = NULL;
    int ret;
    EVP_PKEY_CTX* ctx;

    // create a new BIO for the Base64 result
    BIO* b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
    {
        fprintf(stderr, "Error with BIO_f_base64(): NULL\n");
        return NULL;
    }

    // set the BIO flags to ignore newline characters
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // create a new BIO to hold the peer public key
    BIO* mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
    {
        fprintf(stderr, "Error with BIO_new(): NULL\n");
        return NULL;
    }

    // put the peer public key into the BIO
    BIO_puts(mem, (const char*)peer_public_key);

    // push b64 onto mem
    mem = BIO_push(b64, mem);

    // convert the peer_public_key into the b64
    d2i_PUBKEY_bio(b64, &peer_key);
    if (peer_key == NULL)
    {
        fprintf(stderr, "Error with d2i_PUBKEY_bio(): NULL\n");
        return NULL;
    }

    // create a new context for the shared secret derivation
    ctx = EVP_PKEY_CTX_new(key_info, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Error with EVP_PKEY_CTX_new(): NULL\n");
        return NULL;
    }

    // initialize the context
    ret = EVP_PKEY_derive_init(ctx);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_derive_init(): %d\n", ret);
        return NULL;
    }

    // provide the peer_public_key
    ret = EVP_PKEY_derive_set_peer(ctx, peer_key);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_derive_set_peer(): %d\n", ret);
        return NULL;
    }

    size_t secret_len;

    // determine the buffer length for the shared secret
    ret = EVP_PKEY_derive(ctx, NULL, &secret_len);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_derive(): %d\n", ret);
        return NULL;
    }

    // allocate space to hold the ECDH shared secret
    unsigned char* secret = malloc(secret_len * sizeof(unsigned char));
    if (secret == NULL)
    {
        fprintf(stderr, "Error with malloc(secretLen): NULL\n");
        return NULL;
    }

    // derive the ECDH shared secret
    ret = EVP_PKEY_derive(ctx, secret, &secret_len);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_derive(): %d\n", ret);
        return NULL;
    }

    // hash the ECDH shared secret with SHA-256
    unsigned char* sha256_key = sha256Key(secret, secret_len);
    if (sha256_key == NULL)
    {
        fprintf(stderr, "Error with Sha256Key(): NULL\n");
        return NULL;
    }

    // Base64 encode the SHA-256 hashed ECDH shared secret
    char* base64_result = base64Encode(sha256_key, secret_len);
    if (base64_result == NULL)
    {
        fprintf(stderr, "Error with Base64Encode(): NULL\n");
        return NULL;
    }

    free(secret);
    // free the buffer that holds the SHA-256 hashed ECDH shared secret
    free(sha256_key);

    // return the Base64 encoded SHA-256 hashed ECDH shared secret
    return base64_result;
}

// Creates the public key within key_info
// Given the kctx and key_info
// Returns this device's public key
// The returned buffer needs to be freed from the heap
char* getPublicKey(EVP_PKEY_CTX** kctx, EVP_PKEY** key_info)
{
    int ret;
    EVP_PKEY_CTX* pctx;
    EVP_PKEY* params = NULL;

    // create the context for parameter generation
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL)
    {
        fprintf(stderr, "Error with EVP_PKEY_CTX_new_id(): NULL\n");
        return NULL;
    }

    // initialize the parameter generation
    ret = EVP_PKEY_paramgen_init(pctx);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_paramgen_init(): %d\n", ret);
        return NULL;
    }

    // set the parameter to use the ANSI X9.62 Prime 256v1 curve
    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_CTX_set_ec_paramgen_curve_nid(): %d\n", ret);
        return NULL;
    }

    // create the object parameters
    ret = EVP_PKEY_paramgen(pctx, &params);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_paramgen(): %d\n", ret);
        return NULL;
    }

    // create the context for the key generation
    *kctx = EVP_PKEY_CTX_new(params, NULL);
    if (*kctx == NULL)
    {
        fprintf(stderr, "Error with EVP_PKEY_CTX_new(): NULL\n");
        return NULL;
    }

    // initialize the key generation
    ret = EVP_PKEY_keygen_init(*kctx);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_keygen_init(): %d\n", ret);
        return NULL;
    }

    // generate the key
    ret = EVP_PKEY_keygen(*kctx, key_info);
    if (ret != 1)
    {
        fprintf(stderr, "Error with EVP_PKEY_keygen(): %d\n", ret);
        return NULL;
    }

    // extract the public key from the PEM formatted file
    char* public_key = getPemKey(*key_info);

    EVP_PKEY_CTX_free(pctx);

    // return the public key string
    return public_key;
}
