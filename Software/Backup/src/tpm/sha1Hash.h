#ifndef _SHA1_H
#define _SHA1_H
#include <asf.h>


typedef struct
{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
}
hashContext;

/*
 * Core SHA-1 functions
 */
void sha1_starts_t( hashContext *ctx );
void sha1_update_t( hashContext *ctx, uint8_t *input, uint32_t length );
void sha1_finish_t( hashContext *ctx, uint8_t *digest );
uint8_t sha1_self_test(void);
void sha1_process_t( hashContext *ctx, uint8_t *data );
/*
 * Output SHA-1(file contents), returns 0 if successful.
 */
int sha1_file_t( char *filename, uint8_t* digest);

/*
 * Output SHA-1(buf)
 */
void sha1_csum_t( uint8_t *buf, uint32_t buflen, uint8_t* digest);

/*
 * Output HMAC-SHA-1(key,buf)
 */
void sha1_hmac_t( uint8_t *key, uint32_t keylen, uint8_t *buf, uint32_t buflen,
                uint8_t* digest );

/*
 * Checkup routine
 */
int sha1_self_test_t( void );

#ifdef __cplusplus
}
#endif

#endif /* sha1.h */
