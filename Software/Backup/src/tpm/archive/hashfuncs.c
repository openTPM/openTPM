#include <string.h>
#include "hashFuncs.h"

// local protos
static void unpackShaH(U32 *h, U8 *dest);
#define LITTLE_ENDIAN

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                    \
{                                               \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif
#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}
#endif



// initialized globals
static U32 hashContext_h_init[] = {
#ifdef LITTLE_ENDIAN
	0x67452301L,
	0xefcdab89L,
	0x98badcfeL,
	0x10325476L,
	0xc3d2e1f0L
#else
	0x01234567L,
	0x89abcdefL,
	0xfedcba98L,
	0x76543210L,
	0xf0e1d2c3L
#endif


};

void (sha1_start)(hashContext *ctx) {
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->h, hashContext_h_init, sizeof(ctx->h));
}

void (sha1_update)(hashContext *ctx, U8 *src, int nbytes) {

	/*
	Digest src bytes, updating context.
	*/

	U8 i,freeBytes;
	U32 temp32;

	// Get number of free bytes in the buf
	freeBytes = (U8)(ctx->byteCount);							// always 0 after hashInit
	freeBytes &= 63;
	freeBytes = (U8)(64 - freeBytes);

	while (nbytes > 0) {

		// Get i, number of bytes to transfer from src
		i = freeBytes;
		if (nbytes < i) i = (U8)nbytes;							// i = nybytes if < freeBytes, otherwise freeBytes

		// Copy src bytes to buf
		memcpy(ctx->buf + 64 - freeBytes, src, i);				// fill from end of ctx->buf (i bytes)
		src += i;												// move src ptr i bytes forward
		nbytes -= i;											// decrement src nbytes by i
		freeBytes -= i;											// decrement freeBytes by i

		// Do SHA crunch if buf is full
		if (freeBytes == 0) {									// if no freeBytes in ctx-buf, do SHA
			shaEngine(ctx->buf, ctx->h);
		}

		// Update 64-bit byte count
		temp32 = (ctx->byteCount += i);
		if (temp32 == 0) ++ctx->byteCountHi;

		// Set up for next iteration
		freeBytes = 64;
	}
}

void (sha1_finish)(hashContext *ctx, U8 *dest) {

	/*
	Finish a hash calculation and put result in dest.
	*/

	U8 i;
	U8 nbytes;
	U32 temp;
	U8 *ptr;

	/* Append pad byte, clear trailing bytes */
	nbytes = (U8)(ctx->byteCount) & 63;
	ctx->buf[nbytes] = 0x80;
	for (i = (nbytes+1); i<64; i++) ctx->buf[i] = 0;

	/*
	If no room for an 8-byte count at end of buf, digest the buf,
	then clear it
	*/
	if (nbytes > (64-9)) {
		shaEngine(ctx->buf, ctx->h);
		memset(ctx->buf, 0, 64);
	}

	/*
	Put the 8-byte bit count at end of buf.  We have been tracking
	bytes, not bits, so we left-shift our byte count by 3 as we do
	this.
	*/
	temp = ctx->byteCount << 3;  // low 4 bytes of bit count
	ptr = &ctx->buf[63];   // point to low byte of bit count
	for (i=0; i<4; i++) {
		*ptr-- = (U8)temp;
		temp >>= 8;
	}
	//
	temp = ctx->byteCountHi << 3;
	temp |= ctx->byteCount >> (32-3); // high 4 bytes of bit count
	for (i=0; i<4; i++) {
		*ptr-- = (U8)temp;
		temp >>= 8;
	}
	//show("final SHA crunch", ctx->buf, 64);

	/* Final digestion */
	shaEngine(ctx->buf, ctx->h);

	/* Unpack chaining variables to dest bytes. */
	unpackShaH(ctx->h, dest);
}


void (sha1_csum)(U8 *msg, int msgBytes, U8 *dest) {
	static hashContext ctx;
	sha1_start(&ctx);
	sha1_update(&ctx, msg, msgBytes);
	sha1_finish(&ctx, dest);
}

//void (sha1_hmac)(U8 *msg, int msgBytes, U8 *key, U8 keyBytes, U8 *dest) {
void (sha1_hmac)(U8 *key, U8 keyBytes, U8 *msg, int msgBytes, U8 *dest) {
	hashContext ctx;
	hmac_start(&ctx, key, keyBytes);
	hmac_update(&ctx, msg, msgBytes);
	hmac_finish(&ctx, key, keyBytes, dest);
}

void (hmac_start)(hashContext *ctx, U8 *key, U8 keyBytes) {

	U8 i;
	U8 temp;
	enum {IPAD = 0x36};

	//
	// Assume keyBytes <= 64
	//

	sha1_start(ctx);

	for (i=0; i<keyBytes; i++) {
		temp = key[i] ^ IPAD;
		sha1_update(ctx, &temp, 1);
	}
	temp = IPAD;
	for (; i<64; i++) {
		sha1_update(ctx, &temp, 1);
	}

}

void (hmac_update)(hashContext *ctx, U8 *src, int nbytes) {
	sha1_update(ctx, src, nbytes);
}

void (hmac_finish)(
	hashContext *ctx, U8 *key, U8 keyBytes, U8 *dest )
{

	U8 i;
	U8 temp;

	enum {OPAD = 0x5c};

	//
	// Assume keyBytes <= 64.
	//
	// Dest may not overlay ctx.
	//

	// Finish hash in progress, save in dest
	sha1_finish(ctx, dest);

	sha1_start(ctx);
	for (i=0; i<keyBytes; i++) {
		temp = key[i] ^ OPAD;
		sha1_update(ctx, &temp, 1);
	}
	temp = OPAD;
	for (; i<64; i++) {
		sha1_update(ctx, &temp, 1);
	}

	sha1_update(ctx, dest, 20);
	sha1_finish(ctx, dest);

}


void shaEngine(U8 *data, U32 *h)
{
    uint32_t temp, W[16], A, B, C, D, E;

    GET_UINT32_BE( W[0],  data,  0 );
    GET_UINT32_BE( W[1],  data,  4 );
    GET_UINT32_BE( W[2],  data,  8 );
    GET_UINT32_BE( W[3],  data, 12 );
    GET_UINT32_BE( W[4],  data, 16 );
    GET_UINT32_BE( W[5],  data, 20 );
    GET_UINT32_BE( W[6],  data, 24 );
    GET_UINT32_BE( W[7],  data, 28 );
    GET_UINT32_BE( W[8],  data, 32 );
    GET_UINT32_BE( W[9],  data, 36 );
    GET_UINT32_BE( W[10], data, 40 );
    GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 );
    GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 );
    GET_UINT32_BE( W[15], data, 60 );

    #define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

    #define R(t)                                            \
    (                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
    W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
    )

    #define P(a,b,c,d,e,x)                                  \
    {                                                       \
	    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
    }

    A = h[0];
    B = h[1];
    C = h[2];
    D = h[3];
    E = h[4];

    #define F(x,y,z) (z ^ (x & (y ^ z)))
    #define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

    #undef K
    #undef F

    #define F(x,y,z) (x ^ y ^ z)
    #define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

    #undef K
    #undef F

    #define F(x,y,z) ((x & y) | (z & (x | y)))
    #define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

    #undef K
    #undef F

    #define F(x,y,z) (x ^ y ^ z)
    #define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

    #undef K
    #undef F

    A = h[0];
    B = h[1];
    C = h[2];
    D = h[3];
    E = h[4];

}


#define leftRotate(x,n) (x) = (((x)<<(n)) | ((x)>>(32-(n))))

static void unpackShaH(U32 *h, U8 *dest) {
	U32 temp;
	U8 i;
	for (i=0; i < 5; i++) {
		temp = h[i];
#ifdef LITTLE_ENDIAN
		dest[3] = (U8)temp; temp >>= 8;
		dest[2] = (U8)temp; temp >>= 8;
		dest[1] = (U8)temp; temp >>= 8;
		dest[0] = (U8)temp;
#else
		dest[0] = (U8)temp; temp >>= 8;
		dest[1] = (U8)temp; temp >>= 8;
		dest[2] = (U8)temp; temp >>= 8;
		dest[3] = (U8)temp;
		dest += 4;
#endif
	}
}

