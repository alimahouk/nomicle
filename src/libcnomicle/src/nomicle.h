//
//  nomicle.h
//  libcnomicle
//
//  NOTE: if building on macOS, make sure to link against your
//  own build of OpenSSL libraries, not Apple's. If you installed
//  OpenSSL via Homebrew, they should be under /use/local/opt/openssl.
//
//  Created by alimahouk on 23/11/2019.
//

#ifndef NOMICLE_H
#define NOMICLE_H

#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#define NCLE_CHECKSUM_LEN       8
#define NCLE_MAGIC_NUM          { 0x89, 0x50, 0x44, 0x48, 0x5a, 0x0d, 0x0a, 0x1a, 0x0a }
#define NCLE_MAGIC_NUM_LEN      9
#define NCLE_ID_VERSION         1
#define NCLE_BITS_BASE          0x1f00ffff
#define NCLE_TOKEN_LEN          32

struct nomicle
{
        ECDSA_SIG *sig;                         /* The signature used to verify the private key that owns this identity. */
        EVP_PKEY *pub_key;                      /* The public key of the owner; can be verified by the signature. */
        unsigned char hash[NCLE_CHECKSUM_LEN];  /* First NCLE_CHECKSUM_LEN bytes of the SHA256 checksum of the entire struct. */
        unsigned char token[NCLE_TOKEN_LEN];    /* The identity token hash. */
        int64_t timestamp_created;              /* Unix timestamp as seconds since 1970-01-01T00:00 UTC until the time that this identity was created. */
        int64_t timestamp_updated;              /* Unix timestamp as seconds since 1970-01-01T00:00 UTC until the time that this identity was last updated. */
        uint64_t extra_nonce;                   /* Used when the nonce overflows. */
        uint64_t nonce;                         /* A counter to be incremented for varying the block's hash. */
        uint8_t version;                        /* Identity version number. */
        uint32_t bits;                          /* The calculated difficulty target being used for this identity. */
};

#ifdef __cplusplus
extern "C"
{
#endif

void id_free(struct nomicle **);
void id_init(const char *,
             EVP_PKEY *,
             struct nomicle **);

int blockcmp(const struct nomicle *,
             const struct nomicle *);

void block_deserialise(const unsigned char *,
                       size_t,
                       struct nomicle **);

/**
 * Writes a block to a file at the given path.
 */
void block_dump(struct nomicle *,
                const char *,
                EVP_PKEY *);

/**
 * Reads a block from the file at the given path.
 * @return 0 if the block was read and serialised successfully,
 * 1 if the block was read but serialisation failed, or -1 if
 * an error occured while attempting to read the file at the
 * given path.
 */
int block_read(const char *,
               struct nomicle **);

size_t block_serialise(struct nomicle *,
                       unsigned char **,
                       EVP_PKEY *);

/**
 * Initialise the OpenSSL library.
 */
void crypto_init(void);

/**
 * Calculates a checksum of the given block.
 */
void hash(const struct nomicle *,
          unsigned char[SHA256_DIGEST_LENGTH]);
void key_fetch(const char *,
               EVP_PKEY **);
void key_gen(EVP_PKEY **);

/**
 * Signs the given digest (typically a block's hash) with the given private key.
 */
ECDSA_SIG *sign(const unsigned char *,
                int,
                EVP_PKEY *);

void target_unpack(const uint32_t,
                   unsigned int *,
                   unsigned int *,
                   BIGNUM **);

#ifdef __cplusplus
}
#endif

#endif /* NOMICLE_H */
