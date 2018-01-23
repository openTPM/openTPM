#include <string.h>
#include "hashFuncs.h"

// local protos
static void unpackShaH(U32 *h, U8 *dest);
#define LITTLE_ENDIAN
//#define HASH_SELF_TEST


#define leftRotate(x,n) (x) = (((x)<<(n)) | ((x)>>(32-(n))))
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

void shaEngine(U8 *buf, U32 *h)
{

/*
	SHA-1 Engine.  From FIPS 180.

	On entry, buf[64] contains the 64 bytes to digest.  These bytes
	are destroyed.

	H[5] contains the 5 chaining variables.  They must have the
	proper value on entry and are updated on exit.
	*/

	U8 t;
	U32 a, b, c, d, e;
	U32 temp ={0};
	U32 *w = (U32*)buf;

	/*
	Pack first 64 bytes of buf into w[0,...,15].  Within a word,
	bytes are big-endian.  Do this in place -- buf[0,...,63]
	overlays w[0,...,15].
	*/
	for (t=0; t<16; t++) {
		temp = (temp << 8) | *buf++;
		temp = (temp << 8) | *buf++;
		temp = (temp << 8) | *buf++;
		temp = (temp << 8) | *buf++;
		w[t] = temp;
	}

	/* Copy the chaining variables to a, b, c, d, e */
	a = h[0];
	b = h[1];
	c = h[2];
	d = h[3];
	e = h[4];

	/* Now do the 80 rounds */
	for (t=0; t<80; t++) {

		temp = a;
		leftRotate(temp, 5);
		temp += e;
		temp += w[t&0xf];

		if (t < 20) {
			temp += (b & c) | (~b & d);
			temp += 0x5a827999L;
		}
		else if (t < 40) {
			temp += b ^ c ^ d;
			temp += 0x6ed9eba1L;
		}
		else if (t < 60) {
			temp += (b & c) | (b & d) | (c & d);
			temp += 0x8f1bbcdcL;
		}
		else {
			temp += b ^ c ^ d;
			temp += 0xca62c1d6L;
		}

		e = d;
		d = c;
		c = b; leftRotate(c, 30);
		b = a;
		a = temp;

		temp = w[t&0xf] ^ w[(t-3)&0xf] ^ w[(t-8)&0xf] ^ w[(t-14)&0xf];
		leftRotate(temp, 1);
		w[t&0xf] = temp;

	}

	/* Update the chaining variables */
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;



}




static void unpackShaH(U32 *h, U8 *dest)
{
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
#endif

		dest += 4;

	}
}
	
	
	
#ifdef HASH_SELF_TEST
/*
 * FIPS-180-1 test vectors
 */
static const char *sha1_test_str[3] =
{
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL
};

static uint8_t sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};
	
/*
 * Checkup routine
 */
uint8_t sha1_self_test( )
{
    static int i, j; 
    static uint8_t buf[1000];
    static uint8_t sha1sum[20];
    hashContext ctx;

    i =0;
	sha1_csum((uint8_t *) sha1_test_str[i], strlen( sha1_test_str[i] ), (uint8_t *)sha1sum);

	if( memcmp( sha1sum, sha1_test_sum[i], 20 ) != 0 )
	{
		asm("nop");
		return( 1 );
	}

	asm("nop");
	return( 0 );
	
	
}
#endif

