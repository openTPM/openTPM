#ifndef HASHFUNCS_H
#define HASHFUNCS_H

#include <asf.h>

// typedefs
typedef unsigned char U8;
//typedef unsigned int U16;
typedef unsigned long U32;

typedef struct {
	U32 h[5];
	U32 byteCount;
	U32 byteCountHi;
	U8 buf[64];
} hashContext;

// prototypes
void sha1_csum(U8 *msg, int msgBytes, U8 *dest);
//void sha1_hmac(U8 *msg, int msgBytes, U8 *key, U8 keyBytes, U8 *dest);
void sha1_hmac(U8 *key, U8 keyBytes, U8 *msg, int msgBytes, U8 *dest);
void shaEngine(U8 *buf, U32 *h);

void sha1_start(hashContext *ctx);
void sha1_update(hashContext *ctx, U8 *src, int nbytes);
void sha1_finish(hashContext *ctx, U8 *dest);
uint8_t sha1_self_test(void);

// void sha1_begin(sha1_ctx ctx[1]);
// void sha1_hash(const unsigned char data[], unsigned int len, sha1_ctx ctx[1]);
// void sha1_end(unsigned char hval[], sha1_ctx ctx[1]);
// void sha1(unsigned char hval[], const unsigned char data[], unsigned int len);

void hmac_start(hashContext *ctx, U8 *key, U8 keyBytes);
void hmac_update(hashContext *ctx, U8 *src, int nbytes);
void hmac_finish(hashContext *ctx, U8 *key, U8 keyBytes, U8 *dest);

#endif
