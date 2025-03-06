//
//  nomicle.c
//  libcnomicle
//
//  Created by alimahouk on 23/11/2019.
//

#include "nomicle.h"

#include <assert.h>
#include <math.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>


/* PRIVATE PROTOTYPES
 **********************/

/**
 * Converts a BIGNUM into an unsigned integer.
 */
void bntoui(BIGNUM *,
            unsigned int *);

/**
 * Creates a string representation of a double.
 */
void dtoc(double,
          char **);

ECDSA_SIG *ecdsa_sign(const unsigned char *,
                      int,
                      EVP_PKEY *);

/**
 * Verfies that a signature was created by the private half of the given
 * public key.
 * @return 1 if the signature is okay, 0 if the signature is incorrect, or
 * -1 if an error occured.
 */
int ecdsa_verify(const unsigned char *,
                 int,
                 ECDSA_SIG *,
                 EVP_PKEY *);

FILE *file_make(const char *);

/**
 * Returns the handle of the given file (if it exists) for reading.
 * @return The file handle.
 */
FILE *file_open(const char *);

/**
 * Reads the binary file at the given path into the given buffer. It is the
 * caller's duty to free the buffer.
 * @return The number of bytes read.
 */
off_t file_readb(const char *,
                 unsigned char **);

/**
 * Writes the bytes to a file at the given path in binary mode.
 * @return The number of bytes written.
 */
off_t file_writeb(const char *,
                  const unsigned char *,
                  size_t);

/**
 * Converts DER data into a public key.
 * @return The key.
 */
EVP_PKEY *key_decode(unsigned char **,
                     size_t);

/**
 * Saves the given key to the disk in PEM format.
 * @return 0 on success, 1 if the file could not be created, or -1 if there
 * was a problem with the passed key.
 */
int key_dump(EVP_PKEY *,
             const char *);

/**
 * Converts a public key into DER format.
 * @return The length of the data, or -1 if an error occurred.
 */
int key_encode(EVP_PKEY *,
               unsigned char **);
void key_read(EVP_PKEY **,
              const char *);

/**
 * Generates the SHA-256 hash of the given binary data.
 * @attention @param digest should be of size SHA256_DIGEST_LENGTH.
 */
void sha(const unsigned char *,
         size_t,
         unsigned char[SHA256_DIGEST_LENGTH]);

/**
 * Decodes a DER-encoded ECDSA signature.
 * @return A pointer to the ECDSA_SIG structure or NULL.
 */
ECDSA_SIG *sig_decode(unsigned char **,
                      size_t);

/**
 * DER-encodes the contents of a ECDSA_SIG object.
 * @return The length of the DER encoded ECDSA_SIG object or 0.
 */
int sig_encode(const ECDSA_SIG *,
               unsigned char **);

/**
 * Creates a BigNum out of an unsigned integer.
 */
void uitobn(const unsigned int,
            BIGNUM **);

/**
 * Creates a string representation of an unsigned integer.
 */
void uitoc(unsigned int,
           char **);

/***********************/

void id_free(struct nomicle **id)
{
        if (id
            && *id)
        {
                if ((*id)->pub_key)
                        EVP_PKEY_free((*id)->pub_key);
                
                if ((*id)->sig)
                        ECDSA_SIG_free((*id)->sig);
                
                free(*id);
                *id = NULL;
        }
}

void id_init(const char *identifier,
             EVP_PKEY *pub_key,
             struct nomicle **id)
{
        if (identifier
            && pub_key && id)
        {
                *id = (struct nomicle *)malloc(sizeof(struct nomicle));
                if (*id)
                {
                        memset((*id)->hash, 0, NCLE_CHECKSUM_LEN);
                        memset((*id)->token, 0, NCLE_TOKEN_LEN);
                        
                        (*id)->extra_nonce = 0;
                        (*id)->nonce = 0;
                        (*id)->pub_key = EVP_PKEY_new();
                        (*id)->sig = NULL;
                        (*id)->bits = NCLE_BITS_BASE; /* Start at the highest possible target (difficulty 1, 0x1d00ffff) by default. */
                        (*id)->timestamp_created = time(NULL);
                        (*id)->timestamp_updated = time(NULL);
                        (*id)->version = NCLE_ID_VERSION;
                        /* Make a copy of the key. */
                        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pub_key);
                        EC_KEY *ec_key_dup = EC_KEY_dup(ec_key);
                        EC_KEY_free(ec_key);
                        EVP_PKEY_assign_EC_KEY((*id)->pub_key, ec_key_dup);
                        /* Hash the token string. */
                        sha((unsigned char *)identifier, strlen(identifier), (*id)->token);
                }
        }
}

int blockcmp(const struct nomicle *id1,
             const struct nomicle *id2)
{
        BIGNUM *target1;
        BIGNUM *target2;
        unsigned int exp1;
        unsigned int exp2;
        unsigned int mantissa1;
        unsigned int mantissa2;
        
        target_unpack(id1->bits, &exp1, &mantissa1, &target1);
        target_unpack(id2->bits, &exp2, &mantissa2, &target2);
        
        return BN_cmp(target1, target2);
}

void block_deserialise(const unsigned char *bytes,
                       size_t len,
                       struct nomicle **id)
{
        if (bytes
            && id)
        {
                unsigned char digest[SHA256_DIGEST_LENGTH];
                unsigned char magic_num[NCLE_MAGIC_NUM_LEN] = NCLE_MAGIC_NUM;
                unsigned char *key_data;
                unsigned char *sig_data;
                int offset;
                int32_t key_len;
                int32_t sig_len;
                
                /* 1) Magic number */
                if (memcmp(bytes, magic_num, NCLE_MAGIC_NUM_LEN * sizeof(unsigned char)) != 0)
                {
                        *id = NULL;
                        fprintf(stderr, "libcnomicle.deserialise(3): invalid magic number!");
                        return;
                }
                
                *id = (struct nomicle *)malloc(sizeof(struct nomicle));
                offset = NCLE_MAGIC_NUM_LEN;
                /* 2) Protocol version (1 byte) */
                (*id)->version = bytes[offset];
                offset += sizeof(uint8_t);
                /* 3) Block hash (CHECKSUM_LEN bytes) */
                memcpy((*id)->hash, &bytes[offset], NCLE_CHECKSUM_LEN * sizeof(unsigned char));
                offset += NCLE_CHECKSUM_LEN * sizeof(unsigned char);
                /* 4) Signature size (2 bytes) */
                sig_len = bytes[offset + 1] |
                ((uint16_t)bytes[offset] << 8);
                offset += sizeof(uint16_t);
                /* 5) Signature */
                sig_data = malloc(sig_len * sizeof(unsigned char));
                if (sig_data)
                {
                        memcpy(sig_data, &bytes[offset], sig_len * sizeof(unsigned char));
                        (*id)->sig = sig_decode(&sig_data, sig_len);
                        free(sig_data);
                        sig_data = NULL;
                        
                        /* Check if the signature is a valid ECDSA signature. */
                        if ((*id)->sig == NULL)
                        {
                                free(*id);
                                *id = NULL;
                                fprintf(stderr, "libcnomicle.deserialise(3): signature is not a valid ECDSA signature!");
                                return;
                        }
                }
                
                offset += sig_len;
                /* 6) Identity token hash (32 bytes) */
                memcpy((*id)->token, &bytes[offset], NCLE_TOKEN_LEN * sizeof(unsigned char));
                offset += NCLE_TOKEN_LEN;
                /* 7) Bits (4 bytes) */
                (*id)->bits = bytes[offset + 3] |
                        ((uint32_t)bytes[offset + 2] << 8) |
                        ((uint32_t)bytes[offset + 1] << 16) |
                        ((uint32_t)bytes[offset] << 24);
                offset += sizeof(uint32_t);
                /* 8) Nonce (8 bytes) */
                (*id)->nonce = bytes[offset + 7] |
                        ((uint64_t)bytes[offset + 6] << 8) |
                        ((uint64_t)bytes[offset + 5] << 16) |
                        ((uint64_t)bytes[offset + 4] << 24) |
                        ((uint64_t)bytes[offset + 3] << 32) |
                        ((uint64_t)bytes[offset + 2] << 40) |
                        ((uint64_t)bytes[offset + 1] << 48) |
                        ((uint64_t)bytes[offset] << 56);
                offset += sizeof(uint64_t);
                /* 9) Extra nonce (8 bytes) */
                (*id)->extra_nonce = bytes[offset + 7] |
                        ((uint64_t)bytes[offset + 6] << 8) |
                        ((uint64_t)bytes[offset + 5] << 16) |
                        ((uint64_t)bytes[offset + 4] << 24) |
                        ((uint64_t)bytes[offset + 3] << 32) |
                        ((uint64_t)bytes[offset + 2] << 40) |
                        ((uint64_t)bytes[offset + 1] << 48) |
                        ((uint64_t)bytes[offset] << 56);
                offset += sizeof(uint64_t);
                /* 10) Timestamp Created (8 bytes) */
                (*id)->timestamp_created = bytes[offset + 7] |
                        ((int64_t)bytes[offset + 6] << 8) |
                        ((int64_t)bytes[offset + 5] << 16) |
                        ((int64_t)bytes[offset + 4] << 24) |
                        ((int64_t)bytes[offset + 3] << 32) |
                        ((int64_t)bytes[offset + 2] << 40) |
                        ((int64_t)bytes[offset + 1] << 48) |
                        ((int64_t)bytes[offset] << 56);
                offset += sizeof(int64_t);
                /* 11) Timestamp Updated (8 bytes) */
                (*id)->timestamp_updated = bytes[offset + 7] |
                        ((int64_t)bytes[offset + 6] << 8) |
                        ((int64_t)bytes[offset + 5] << 16) |
                        ((int64_t)bytes[offset + 4] << 24) |
                        ((int64_t)bytes[offset + 3] << 32) |
                        ((int64_t)bytes[offset + 2] << 40) |
                        ((int64_t)bytes[offset + 1] << 48) |
                        ((int64_t)bytes[offset] << 56);
                offset += sizeof(int64_t);
                /* 12) Public key size (2 bytes) */
                key_len = bytes[offset + 1] |
                        ((uint16_t)bytes[offset] << 8);
                offset += sizeof(uint16_t);
                /* 13) Public key */
                key_data = malloc(key_len * sizeof(unsigned char));
                if (key_data)
                {
                        memcpy(key_data, &bytes[offset], key_len * sizeof(unsigned char));
                        (*id)->pub_key = key_decode(&key_data, key_len);
                        free(key_data);
                        key_data = NULL;
                        /* Check if the key is a valid EC public key. */
                        if ((*id)->pub_key == NULL)
                        {
                                free(*id);
                                *id = NULL;
                                fprintf(stderr, "libcnomicle.deserialise(3): invalid EC public key!");
                                return;
                        }
                }
                offset += key_len;
                
                /* Verify the hash. Remeber that only the first CHECKSUM_LEN bytes are actually stored. */
                hash(*id, digest);
                if (memcmp(digest, (*id)->hash, NCLE_CHECKSUM_LEN * sizeof(unsigned char)) != 0)
                {
                        free(*id);
                        *id = NULL;
                        fprintf(stderr, "libcnomicle.deserialise(3): invalid checksum!");
                        return;
                }
                /* Verify the signature. */
                if (ecdsa_verify(digest, SHA256_DIGEST_LENGTH, (*id)->sig, (*id)->pub_key) != 1)
                {
                        free(*id);
                        *id = NULL;
                        fprintf(stderr, "libcnomicle.deserialise(3): invalid signature!");
                        return;
                }
        }
}

void block_dump(struct nomicle *id,
                const char *path,
                EVP_PKEY *priv_key)
{
        if (id
            && path)
        {
                unsigned char *bytes;
                size_t len = block_serialise(id, &bytes, priv_key);
                
                if (bytes)
                        file_writeb(path, bytes, len);
        }
}

int block_read(const char *path,
               struct nomicle **id)
{
        unsigned char *bytes;
        int ret = (int)file_readb(path, &bytes);
        
        if (bytes)
        {
                block_deserialise(bytes, ret, id);
                
                if (*id)
                        ret = 0;
                else
                        ret = 1;
                
                free(bytes);
        }
        
        return ret;
}

size_t block_serialise(struct nomicle *id,
                       unsigned char **bytes,
                       EVP_PKEY *priv_key)
{
        size_t len = 0;
        
        if (id
            && bytes)
        {
                if (priv_key)
                {
                        /*
                         * Calculate a hash of the block, store it within,
                         * then sign it.
                         */
                        unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
                        
                        hash(id, digest);
                        memcpy(id->hash, digest, NCLE_CHECKSUM_LEN);
                        
                        id->sig = sign(digest, SHA256_DIGEST_LENGTH, priv_key);
                }
                
                unsigned char *key_data;
                unsigned char *sig_data;
                off_t offset;
                int32_t key_len;
                int32_t sig_len;
                
                key_len = key_encode(id->pub_key, &key_data);
                sig_len = sig_encode(id->sig, &sig_data);
                
                if (key_data
                    && sig_data)
                {
                        unsigned char magic_num[NCLE_MAGIC_NUM_LEN] = NCLE_MAGIC_NUM;
                        len = key_len + sig_len + NCLE_MAGIC_NUM_LEN + NCLE_CHECKSUM_LEN + NCLE_TOKEN_LEN + sizeof(uint16_t)    /* Signature size */
                                + sizeof(uint16_t)                                                                              /* Public key size */
                                + sizeof(uint8_t)                                                                               /* Version */
                                + sizeof(uint32_t)                                                                              /* Bits */
                                + sizeof(uint64_t)                                                                              /* Nonce */
                                + sizeof(uint64_t)                                                                              /* Extra nonce */
                                + sizeof(int64_t)                                                                               /* Timestamp Created */
                                + sizeof(int64_t);                                                                              /* Timestamp Updated */
                        offset = NCLE_MAGIC_NUM_LEN;
                        
                        *bytes = (unsigned char *)calloc(len, sizeof(unsigned char));
                        if (*bytes)
                        {
                                /* 1) Magic number */
                                memcpy(*bytes, magic_num, NCLE_MAGIC_NUM_LEN * sizeof(unsigned char));
                                /* 2) Protocol version */
                                (*bytes)[offset] = id->version & 0xff;
                                /* 3) Block hash (first CHECKSUM_LEN bytes only)  */
                                memcpy(&(*bytes)[++offset], id->hash, NCLE_CHECKSUM_LEN * sizeof(unsigned char));
                                offset += NCLE_CHECKSUM_LEN;
                                /* 4) Signature size */
                                (*bytes)[offset] = (sig_len >> 8) & 0xff;
                                (*bytes)[++offset] = sig_len & 0xff;
                                /* 5) Signature */
                                memcpy(&(*bytes)[++offset], sig_data, sig_len * sizeof(unsigned char));
                                offset += sig_len;
                                /* 6) Identity token hash */
                                memcpy(&(*bytes)[offset], id->token, NCLE_TOKEN_LEN * sizeof(unsigned char));
                                offset += NCLE_TOKEN_LEN;
                                /* 7) Target */
                                (*bytes)[offset]   = (id->bits >> 24) & 0xff;
                                (*bytes)[++offset] = (id->bits >> 16) & 0xff;
                                (*bytes)[++offset] = (id->bits >> 8) & 0xff;
                                (*bytes)[++offset] = id->bits & 0xff;
                                /* 8) Nonce */
                                (*bytes)[++offset] = (id->nonce >> 56) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 48) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 40) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 32) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 24) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 16) & 0xff;
                                (*bytes)[++offset] = (id->nonce >> 8) & 0xff;
                                (*bytes)[++offset] = id->nonce & 0xff;
                                /* 9) Extra nonce */
                                (*bytes)[++offset] = (id->extra_nonce >> 56) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 48) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 40) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 32) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 24) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 16) & 0xff;
                                (*bytes)[++offset] = (id->extra_nonce >> 8) & 0xff;
                                (*bytes)[++offset] = id->extra_nonce & 0xff;
                                /* 10) Timestamp Created */
                                (*bytes)[++offset] = (id->timestamp_created >> 56) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 48) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 40) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 32) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 24) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 16) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_created >> 8) & 0xff;
                                (*bytes)[++offset] = id->timestamp_created & 0xff;
                                /* 11) Timestamp Updated */
                                (*bytes)[++offset] = (id->timestamp_updated >> 56) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 48) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 40) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 32) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 24) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 16) & 0xff;
                                (*bytes)[++offset] = (id->timestamp_updated >> 8) & 0xff;
                                (*bytes)[++offset] = id->timestamp_updated & 0xff;
                                /* 12) Public key size */
                                (*bytes)[++offset] = (key_len >> 8) & 0xff;
                                (*bytes)[++offset] = key_len & 0xff;
                                /* 13) Public key */
                                memcpy(&(*bytes)[++offset], key_data, key_len * sizeof(unsigned char));
                                offset += key_len;
                        }
                        else
                        {
                                len = 0;
                        }
                }
                
                if (key_data)
                        free(key_data);
                if (sig_data)
                        free(sig_data);
        }
        return len;
}

void bntoui(BIGNUM *bn,
            unsigned int *i)
{
        char *str;
        
        str = BN_bn2dec(bn);
        sscanf(str, "%u", i);
}

void crypto_init(void)
{
        if (SSL_library_init())
        {
                OpenSSL_add_all_ciphers();
                OpenSSL_add_all_digests();
        }
        else
        {
                exit(EXIT_FAILURE);
        }
}

void dtoc(double d,
          char **str)
{
        size_t buff_len = snprintf(NULL, 0, "%f", d);
        *str = (char *)calloc(buff_len + 1, sizeof(char));
        sprintf(*str, "%f", d);
}

ECDSA_SIG *ecdsa_sign(const unsigned char *hash,
                      int hash_len,
                      EVP_PKEY *pkey)
{
        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        return ECDSA_do_sign(hash, hash_len, ec_key);
}

int ecdsa_verify(const unsigned char *hash,
                 int hash_len,
                 ECDSA_SIG *sig,
                 EVP_PKEY *pkey)
{
        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        return ECDSA_do_verify(hash, hash_len, sig, ec_key);
}

FILE *file_make(const char *path)
{
        return fopen(path, "w+");
}

FILE *file_open(const char *path)
{
        return fopen(path, "r");
}

off_t file_readb(const char *path,
                 unsigned char **buffer)
{
        off_t size = 0;
        
        if (buffer)
        {
                FILE *file;
                
                *buffer = NULL;
                file = fopen(path, "rb");
                if (!file)
                {
                        fprintf(stderr, "libcnomicle.file_readb(2): Unable to open file %s", path);
                        size = -1;
                }
                else
                {
                        fseek(file, 0, SEEK_END);
                        size = ftell(file);
                        fseek(file, 0, SEEK_SET);
                        
                        *buffer = (unsigned char *)malloc(size);
                        if (!*buffer)
                        {
                                fprintf(stderr, "libcnomicle.file_readb(2): memory error!");
                                fclose(file);
                                size = -1;
                        }
                        
                        fread(*buffer, size, 1, file);
                        fclose(file);
                }
        }
        return size;
}

off_t file_writeb(const char *path,
                  const unsigned char *buffer,
                  size_t len)
{
        off_t bytes_written = 0;
        
        if (buffer)
        {
                FILE *file = fopen(path, "wb");
                
                if (file)
                {
                        bytes_written = fwrite(buffer, 1, len, file);
                        fclose(file);
                }
        }
        return bytes_written;
}

void hash(const struct nomicle *id,
          unsigned char digest[])
{
        /*
         * We pack everything from the block into a buffer
         * excluding the magic number, signature,
         * and the hash itself (obviously).
         */
        unsigned char *buffer;
        unsigned char *key_data;
        size_t len = 0;
        off_t offset;
        int32_t key_len;
        
        offset = 0;
        key_len = key_encode(id->pub_key, &key_data);
        
        if (key_data)
        {
                len = key_len + NCLE_TOKEN_LEN + sizeof(uint8_t)        /* Version */
                + sizeof(uint32_t)                                      /* Bits */
                + sizeof(uint64_t)                                      /* Nonce */
                + sizeof(uint64_t)                                      /* Extra nonce */
                + sizeof(int64_t)                                       /* Timestamp Created */
                + sizeof(int64_t)                                       /* Timestamp Updated */
                + sizeof(uint16_t);                                     /* Public key size */
                
                buffer = (unsigned char *)calloc(len, sizeof(unsigned char));
                if (buffer)
                {
                        /* 1) Protocol version */
                        (buffer)[offset] = id->version & 0xff;
                        /* 2) Identity token hash */
                        memcpy(&buffer[++offset], id->token, NCLE_TOKEN_LEN * sizeof(unsigned char));
                        offset += NCLE_TOKEN_LEN;
                        /* 3) Target */
                        (buffer)[offset]   = (id->bits >> 24) & 0xff;
                        (buffer)[++offset] = (id->bits >> 16) & 0xff;
                        (buffer)[++offset] = (id->bits >> 8) & 0xff;
                        (buffer)[++offset] = id->bits & 0xff;
                        /* 4) Nonce */
                        (buffer)[++offset] = (id->nonce >> 56) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 48) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 40) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 32) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 24) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 16) & 0xff;
                        (buffer)[++offset] = (id->nonce >> 8) & 0xff;
                        (buffer)[++offset] = id->nonce & 0xff;
                        /* 5) Extra nonce */
                        (buffer)[++offset] = (id->extra_nonce >> 56) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 48) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 40) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 32) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 24) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 16) & 0xff;
                        (buffer)[++offset] = (id->extra_nonce >> 8) & 0xff;
                        (buffer)[++offset] = id->extra_nonce & 0xff;
                        /* 6) Timestamp Created */
                        (buffer)[++offset] = (id->timestamp_created >> 56) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 48) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 40) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 32) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 24) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 16) & 0xff;
                        (buffer)[++offset] = (id->timestamp_created >> 8) & 0xff;
                        (buffer)[++offset] = id->timestamp_created & 0xff;
                        /* 7) Timestamp Updated */
                        (buffer)[++offset] = (id->timestamp_updated >> 56) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 48) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 40) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 32) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 24) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 16) & 0xff;
                        (buffer)[++offset] = (id->timestamp_updated >> 8) & 0xff;
                        (buffer)[++offset] = id->timestamp_updated & 0xff;
                        /* 8) Public key size */
                        (buffer)[++offset] = (key_len >> 8) & 0xff;
                        (buffer)[++offset] = key_len & 0xff;
                        /* 9) Public key */
                        memcpy(&buffer[++offset], key_data, key_len * sizeof(unsigned char));
                        offset += key_len;
                        
                        sha(buffer, len, digest);
                }
        }
        
        if (key_data)
                free(key_data);
}

EVP_PKEY *key_decode(unsigned char **key_bytes,
                     size_t len)
{
        EVP_PKEY *key;
        const unsigned char *q;
        
        q = *key_bytes;
        key = d2i_PUBKEY(NULL, &q, len);
        
        return key;
}

int key_dump(EVP_PKEY *pkey,
             const char *path)
{
        const BIGNUM *private_key;
        EC_KEY *ec_key;
        FILE *f_key;
        int err_no;
        
        ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        err_no = 0;
        
        if (ec_key)
        {
                f_key = file_make(path);
                private_key = EC_KEY_get0_private_key(ec_key);
                
                if (f_key)
                {
                        /*
                         * If we have a private key, don't save the public half as that
                         * can be recomputed from the private key when read from the file.
                         */
                        if (private_key)
                        {
                                if (!PEM_write_ECPrivateKey(f_key, ec_key, NULL, NULL, 0, NULL, NULL))
                                {
                                        ERR_print_errors_fp(stderr);
                                        err_no = EXIT_FAILURE;
                                }
                        }
                        else
                        {
                                /* No private key, just write the public key. */
                                if (!PEM_write_EC_PUBKEY(f_key, ec_key))
                                {
                                        ERR_print_errors_fp(stderr);
                                        err_no = EXIT_FAILURE;
                                }
                        }
                        
                        EC_KEY_free(ec_key);
                        fclose(f_key);
                }
                else
                {
                        err_no = 1;
                }
        }
        else
        {
                err_no = -1;
        }
        return err_no;
}

int key_encode(EVP_PKEY *key,
               unsigned char **buf)
{
        int ret;
        
        ret = -1;
        
        if (buf)
        {
                *buf = NULL;
                if (key)
                {
                        unsigned char *p;
                        size_t buf_len;
                        
                        buf_len = i2d_PUBKEY(key, NULL);
                        *buf = (unsigned char *)malloc(buf_len);
                        
                        p = *buf;
                        ret = i2d_PUBKEY(key, &p);
                }
        }
        return ret;
}

void key_fetch(const char *path,
               EVP_PKEY **pkey)
{
        if (!path
            || !pkey)
                return;
        
        EC_KEY *ec_key;
        FILE *f_key;
        
        ec_key = NULL;
        f_key = file_open(path);
        
        if (f_key)
        {
                ec_key = PEM_read_ECPrivateKey(f_key, NULL, NULL, NULL);
                
                /*
                 * If this is a private key, don't bother trying to open
                 * the public key's file (doesn't exist anyway). The public
                 * key is computed using the private key.
                 */
                if (ec_key)
                        assert(EC_KEY_check_key(ec_key) == 1);
                else
                        /* Not a private key, read as a public key. */
                        ec_key = PEM_read_EC_PUBKEY(f_key, NULL, NULL, NULL);
                
                fclose(f_key);
        }
        
        if (ec_key)
        {
                *pkey = EVP_PKEY_new();
                
                assert(EVP_PKEY_assign_EC_KEY(*pkey, ec_key) == 1);
        }
}

void key_gen(EVP_PKEY **pkey)
{
        if (!pkey)
                return;
        
        BIO *bio;
        EC_KEY *ec_key;
        
        bio = BIO_new(BIO_s_mem());
        ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        *pkey = EVP_PKEY_new();
        
        EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
        
        /* Create the public/private EC key pair here. */
        if (!(EC_KEY_generate_key(ec_key)))
                BIO_printf(bio, "key_gen: error generating the ECC key.");
        
        /*
         * Converting the EC key into a PKEY structure lets us
         * handle the key just like any other key pair.
         */
        if (!EVP_PKEY_assign_EC_KEY(*pkey, ec_key))
                BIO_printf(bio, "key_gen: error assigning ECC key to EVP_PKEY structure.");
        
        /* Cleanup. */
        BIO_free_all(bio);
}

void key_read(EVP_PKEY **pkey,
              const char *path)
{
        if (!path
            || !pkey)
                return;
        
        EC_KEY *ec_key;
        FILE *f_key;
        
        ec_key = NULL;
        f_key = file_open(path);
        
        if (f_key)
        {
                ec_key = PEM_read_ECPrivateKey(f_key, NULL, NULL, NULL);
                
                /*
                 * If this is a private key, don't bother trying to open
                 * the public key's file (doesn't exist anyway). The public
                 * key is computed using the private key.
                 */
                if (ec_key)
                        assert(EC_KEY_check_key(ec_key) == 1);
                else
                /* Not a private key, read as a public key. */
                        ec_key = PEM_read_EC_PUBKEY(f_key, NULL, NULL, NULL);
                
                fclose(f_key);
        }
        
        if (ec_key)
        {
                *pkey = EVP_PKEY_new();
                
                assert(EVP_PKEY_assign_EC_KEY(*pkey, ec_key) == 1);
        }
}

void sha(const unsigned char *data,
         size_t len,
         unsigned char digest[])
{
        SHA256(data, len, (unsigned char *)digest);
}

ECDSA_SIG *sig_decode(unsigned char **sig_bytes,
                      size_t len)
{
        const unsigned char *q = *sig_bytes;
        return d2i_ECDSA_SIG(NULL, &q, len);
}

int sig_encode(const ECDSA_SIG *sig,
               unsigned char **buf)
{
        int ret;
        
        ret = -1;
        
        if (buf)
        {
                *buf = NULL;
                if (sig)
                {
                        unsigned char *p;
                        size_t buff_len;
                        
                        buff_len = i2d_ECDSA_SIG(sig, NULL);
                        *buf = (unsigned char *)malloc(buff_len);
                        
                        p = *buf;
                        ret = i2d_ECDSA_SIG(sig, &p);
                }
        }
        return ret;
}

ECDSA_SIG *sign(const unsigned char *digest,
                int digest_len,
                EVP_PKEY *priv_key)
{
        return ecdsa_sign(digest, digest_len, priv_key);
}

void target_unpack(const uint32_t bits,
                   unsigned int *exponent,
                   unsigned int *mantissa,
                   BIGNUM **target)
{
        BIGNUM *mantissa_bn;
        BIGNUM *pow_base_bn;
        BIGNUM *pow_exponent_bn;
        BIGNUM *pow_result_bn;
        BN_CTX *ctx;
        unsigned int pow_base;
        unsigned int pow_exponent;
        
        *exponent = (bits >> (8 * 3)) & 0xff;
        *mantissa = (bits >> (8 * 0)) & 0xffffff;
        pow_exponent = 0x08 * (*exponent - 0x03);
        
        ctx = BN_CTX_new();
        mantissa_bn = NULL;
        pow_base = 2;
        pow_base_bn = NULL;
        pow_exponent_bn = NULL;
        pow_result_bn = BN_new();
        *target = BN_new();
        
        uitobn(*mantissa, &mantissa_bn);
        uitobn(pow_base, &pow_base_bn);
        uitobn(pow_exponent, &pow_exponent_bn);
        
        BN_exp(pow_result_bn, pow_base_bn, pow_exponent_bn, ctx);
        BN_mul(*target, mantissa_bn, pow_result_bn, ctx);
        
        BN_free(mantissa_bn);
        BN_free(pow_base_bn);
        BN_free(pow_exponent_bn);
        BN_free(pow_result_bn);
        BN_CTX_free(ctx);
}

void uitobn(const unsigned int i,
            BIGNUM **bn)
{
        char *str;
        
        uitoc(i, &str);
        if (str)
        {
                BN_dec2bn(bn, str);
                free(str);
        }
}

void uitoc(const unsigned int i,
           char **str)
{
        size_t buff_len;
        
        buff_len = snprintf(NULL, 0, "%u", i);
        *str = (char *)calloc(buff_len + 1, sizeof(char));
        sprintf(*str, "%u", i);
}
