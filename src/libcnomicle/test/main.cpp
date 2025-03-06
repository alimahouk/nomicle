//
//  main.cpp
//  NCLETest
//
//  The test is written in C++ to test compatibility with C++.
//
//  Created by alimahouk on 27/01/2020.
//

#include <iostream>
#include <nomicle.h>

#define TIMESTAMP_FORM "%Y-%m-%d %H:%M:%S"


/* PROTOTYPES
 ***************/

/**
 * Converts a byte array containing a digest into its hexadecimal string
 * representation.
 */
void dtostr(const unsigned char *,
            size_t,
            char **);

/**
 * @return A Unix timestamp string of the given date & time.
 */
char *timestamp(int64_t);

/***********************/

int main(int argc,
         const char *argv[])
{
        EVP_PKEY *private_key = NULL;
        key_fetch("/usr/local/etc/ncle/privkey.pem", &private_key);
        
        char *block_hash = NULL;
        BIGNUM *target = NULL;
        struct nomicle *id = NULL;
        uint exponent;
        uint mantissa;
        
        /* REPLACE PATH WITH ONE TO AN ACTUAL BLOCK ON YOUR SYSTEM! */
        block_read("/usr/local/var/ncle/blocks/48508b092dfa59c4d9d8f6423c9f17935295641363f86c163a0ee580489393c4.ncle", &id);
        /* Set breakpoint after this line and step through to see if values are correct. */
        if (id)
        {
                dtostr(id->token, SHA256_DIGEST_LENGTH, &block_hash);
                target_unpack(id->bits, &exponent, &mantissa, &target);
                char *target_str = BN_bn2hex(target);
                char *timestamp_created_str = timestamp(id->timestamp_created);
                char *timestamp_updated_str = timestamp(id->timestamp_updated);
                
                free(block_hash);
                free(target_str);
                free(timestamp_created_str);
                free(timestamp_updated_str);
        }
        
        return 0;
}

void dtostr(const unsigned char *digest,
            size_t len,
            char **hex)
{
        if (digest
            && hex)
        {
                *hex = (char *)calloc(len + 1, sizeof(*hex));
                if (*hex)
                        for (int i = 0; i < len; i++)
                                sprintf(&(*hex)[i * 2], "%02x", digest[i]);
        }
}

char *timestamp(int64_t t)
{
        char *buff;
        struct tm *ptm;
        time_t time;
        
        time = t;
        ptm = gmtime(&time);
        buff = (char *)calloc(26, sizeof(char));
        strftime(buff, 25, TIMESTAMP_FORM, ptm);
        
        return buff;
}
