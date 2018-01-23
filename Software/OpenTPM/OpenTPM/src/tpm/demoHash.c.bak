#include <string.h>

typedef unsigned char U8;
typedef unsigned int U16;
typedef unsigned long U32;

void CL_hash(U8 *msg, int msgBytes, U8 *dest);
void CL_hmac(U8 *msg, int msgBytes, U8 *key, U8 keyBytes, U8 *dest);
void shaEngine(U8 *buf, U32 *h);

typedef struct {
	U32 h[5];
	U32 byteCount;
	U32 byteCountHi;
	U8 buf[64];
} hashContext;

void sha1_start(hashContext *ctx);
void sha1_update(hashContext *ctx, U8 *src, int nbytes);
void sha1_finish(hashContext *ctx, U8 *dest);

void hmac_start(hashContext *ctx, U8 *key, U8 keyBytes);
void hmac_update(hashContext *ctx, U8 *src, int nbytes);
void hmac_finish(hashContext *ctx, U8 *key, U8 keyBytes, U8 *dest);


void unpackShaH(U32 *h, U8 *dest);
void unpackShaH(U32 *h, U8 *dest) {
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


void (CL_hash)(U8 *msg, int msgBytes, U8 *dest) {
	hashContext ctx;
	sha1_start(&ctx);
	sha1_update(&ctx, msg, msgBytes);
	sha1_finish(&ctx, dest);
}

void (CL_hmac)(U8 *msg, int msgBytes, U8 *key, U8 keyBytes, U8 *dest) {
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

#define leftRotate(x,n) (x) = (((x)<<(n)) | ((x)>>(32-(n))))

//void shaEngine(U8 *buf, U32 *h) {
//
//	/*
//	SHA-1 Engine.  From FIPS 180.
//
//	On entry, buf[64] contains the 64 bytes to digest.  These bytes
//	are destroyed.
//
//	H[5] contains the 5 chaining variables.  They must have the
//	proper value on entry and are updated on exit.
//	*/
//
//	U8 t;
//	U32 a, b, c, d, e;
//	U32 temp;
//	U32 *w = (U32*)buf;
//
//	/*
//	Pack first 64 bytes of buf into w[0,...,15].  Within a word,
//	bytes are big-endian.  Do this in place -- buf[0,...,63]
//	overlays w[0,...,15].
//	*/
//	for (t=0; t<16; t++) {
//		temp = (temp << 8) | *buf++;
//		temp = (temp << 8) | *buf++;
//		temp = (temp << 8) | *buf++;
//		temp = (temp << 8) | *buf++;
//		w[t] = temp;
//	}
//
//	/* Copy the chaining variables to a, b, c, d, e */
//	a = h[0];
//	b = h[1];
//	c = h[2];
//	d = h[3];
//	e = h[4];
//
//	/* Now do the 80 rounds */
//	for (t=0; t<80; t++) {
//
//		temp = a;
//		leftRotate(temp, 5);
//		temp += e;
//		temp += w[t&0xf];
//
//		if (t < 20) {
//			temp += (b & c) | (~b & d);
//			temp += 0x5a827999L;
//		}
//		else if (t < 40) {
//			temp += b ^ c ^ d;
//			temp += 0x6ed9eba1L;
//		}
//		else if (t < 60) {
//			temp += (b & c) | (b & d) | (c & d);
//			temp += 0x8f1bbcdcL;
//		}
//		else {
//			temp += b ^ c ^ d;
//			temp += 0xca62c1d6L;
//		}
//
//		e = d;
//		d = c;
//		c = b; leftRotate(c, 30);
//		b = a;
//		a = temp;
//
//		temp = w[t&0xf] ^ w[(t-3)&0xf] ^ w[(t-8)&0xf] ^ w[(t-14)&0xf];
//		leftRotate(temp, 1);
//		w[t&0xf] = temp;
//
//	}
//
//	/* Update the chaining variables */
//	h[0] += a;
//	h[1] += b;
//	h[2] += c;
//	h[3] += d;
//	h[4] += e;
//
//}

/*
void sha1_start(hashContext *ctx);
void sha1_update(hashContext *ctx, U8 *src, int nbytes);
void sha1_finish(hashContext *ctx, U8 *dest);

void hmac_start(hashContext *ctx, U8 *key, U8 keyBytes);
void hmac_update(hashContext *ctx, U8 *src, int nbytes);
void hmac_finish(hashContext *ctx, U8 *key, U8 keyBytes, U8 *dest);
*/

int main(void)
{
	U8	message1[] =	{	'a', 'b', 'c'};
	U8	message2[] =	{	'a','b','c','d','b','c','d','e','c','d','e','f','d','e',
							'f','g','e','f','g','h','f','g','h','i','g','h','i','j',
							'h','i','j','k','i','j','k','l','j','k','l','m','k','l',
							'm','n','l','m','n','o','m','n','o','p','n','o','p','q',
						};
	U8	message3[] =	{	'a','a','a','a','a','a','a','a','a','a' };
	U8	HMACkey[] =		{	0x01, 0x02, 0x03 };

	U8	digest[20];
	hashContext ctx;
	U32	bigCounter;

	CL_hash(message1, sizeof(message1),digest);

	sha1_start(&ctx);
	sha1_update(&ctx, message2, sizeof(message2));
	sha1_finish(&ctx, digest);

	sha1_start(&ctx);
	for(bigCounter=0; bigCounter<100000; bigCounter++)
		sha1_update(&ctx, message3, sizeof(message3));
	sha1_finish(&ctx, digest);

//	void CL_hmac(U8 *msg, int msgBytes, U8 *key, U8 keyBytes, U8 *dest);

	CL_hmac(message1, sizeof(message1), HMACkey, sizeof(HMACkey), digest);

	hmac_start(&ctx,  HMACkey, sizeof(HMACkey));
	hmac_update(&ctx, message3, sizeof(message3));
	hmac_finish(&ctx,  HMACkey, sizeof(HMACkey), digest);

	return 0;
}


