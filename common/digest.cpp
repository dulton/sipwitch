// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <config.h>
#include <gnutelephony/digest.h>

#ifdef	HAVE_GCRYPT_CRYPTO
#ifdef	HAVE_GCRYPT_GCRYPT_H
#include <gcrypt/gcrypt.h>
#else
#include <gcrypt.h>
#endif
#define	MD5_GCRYPT
#define	SHA1_GCRYPT
#define	RMD160_GCRYPT
#endif

#ifdef	HAVE_OPENSSL_CRYPTO
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define	MD5Init MD5_Init
#define	MD5Update MD5_Update
#define	MD5Final MD5_Final
#define	SHA1Init SHA1_Init
#define	SHA1Update SHA1_Update
#define	SHA1Final SHA1_Final
#define	RMD160Init RIPEMD160_Init
#define	RMD160Update RIPEMD160_Update
#define	RMD160Final RIPEMD160_Final
#define RMD160_CTX	RIPEMD160_CTX

#define	MD5_GENERIC
#ifdef	OPENSSL_NO_RIPEMD
#define	RMD160_MISSING
#else
#define	RMD160_GENERIC
#endif
#ifdef	OPENSSL_NO_SHA1
#define	SHA1_MISSSING
#else
#define	SHA1_GENERIC
#endif
#endif

#ifdef	HAVE_SASL_CRYPTO
#define	PROTOTYPES 1
#include <sasl/md5global.h>
#include <sasl/md5.h>

#define MD5Init		_sasl_MD5Init
#define	MD5Update	_sasl_MD5Update
#define	MD5Final	_sasl_MD5Final
#define	MD5_GENERIC
#define	SHA1_MISSING
#define	RMD160_MISSING
#endif

#ifdef	HAVE_NO_CRYPTO
#define	MD5_GENERIC
#define	SHA1_MISSING
#define	RMD160_MISSING

typedef struct MD5_CTX {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

#if(__BYTE_ORDER == __LITTLE_ENDIAN)
#define byteReverse(buf, len)	/* Nothing */
#else
static void byteReverse(unsigned char *buf, unsigned longs)
{
	uint32_t t;
	do {
	t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	    ((unsigned) buf[1] << 8 | buf[0]);
	*(uint32_t *) buf = t;
	buf += 4;
	} while (--longs);
}
#endif

static void MD5Init(MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

static void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len)
{
	uint32_t t;

	/* Update bitcount */

	t = ctx->bits[0];
	if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
	ctx->bits[1]++;		/* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

	/* Handle any leading odd-sized chunks */

	if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;

	t = 64 - t;
	if (len < t) {
	    memcpy(p, buf, len);
	    return;
	}
	memcpy(p, buf, t);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += t;
	len -= t;
	}
	/* Process data in 64-byte chunks */

	while (len >= 64) {
	memcpy(ctx->in, buf, 64);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += 64;
	len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(ctx->in, buf, len);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *ctx)
{
	unsigned count;
	unsigned char *p;

	/* Compute number of bytes mod 64 */
	count = (ctx->bits[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset(p, 0, count);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);

	/* Now fill the next block with 56 bytes */
	memset(ctx->in, 0, 56);
	} else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
	}
	byteReverse(ctx->in, 14);

	/* Append length in bits and transform */
	((uint32_t *) ctx->in)[14] = ctx->bits[0];
	((uint32_t *) ctx->in)[15] = ctx->bits[1];

	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	byteReverse((unsigned char *) ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset(ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f /*(x, y, z)*/ + data,  w = w<<s | w>>(32-s),  w += x )

void MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1(b,c,d), a, b, c, d, in[0] + 0xd76aa478L, 7);
	MD5STEP(F1(a,b,c), d, a, b, c, in[1] + 0xe8c7b756L, 12);
	MD5STEP(F1(d,a,b), c, d, a, b, in[2] + 0x242070dbL, 17);
	MD5STEP(F1(c,d,a), b, c, d, a, in[3] + 0xc1bdceeeL, 22);
	MD5STEP(F1(b,c,d), a, b, c, d, in[4] + 0xf57c0fafL, 7);
	MD5STEP(F1(a,b,c), d, a, b, c, in[5] + 0x4787c62aL, 12);
	MD5STEP(F1(d,a,b), c, d, a, b, in[6] + 0xa8304613L, 17);
	MD5STEP(F1(c,d,a), b, c, d, a, in[7] + 0xfd469501L, 22);
	MD5STEP(F1(b,c,d), a, b, c, d, in[8] + 0x698098d8L, 7);
	MD5STEP(F1(a,b,c), d, a, b, c, in[9] + 0x8b44f7afL, 12);
	MD5STEP(F1(d,a,b), c, d, a, b, in[10] + 0xffff5bb1L, 17);
	MD5STEP(F1(c,d,a), b, c, d, a, in[11] + 0x895cd7beL, 22);
	MD5STEP(F1(b,c,d), a, b, c, d, in[12] + 0x6b901122L, 7);
	MD5STEP(F1(a,b,c), d, a, b, c, in[13] + 0xfd987193L, 12);
	MD5STEP(F1(d,a,b), c, d, a, b, in[14] + 0xa679438eL, 17);
	MD5STEP(F1(c,d,a), b, c, d, a, in[15] + 0x49b40821L, 22);

	MD5STEP(F2(b,c,d), a, b, c, d, in[1] + 0xf61e2562L, 5);
	MD5STEP(F2(a,b,c), d, a, b, c, in[6] + 0xc040b340L, 9);
	MD5STEP(F2(d,a,b), c, d, a, b, in[11] + 0x265e5a51L, 14);
	MD5STEP(F2(c,d,a), b, c, d, a, in[0] + 0xe9b6c7aaL, 20);
	MD5STEP(F2(b,c,d), a, b, c, d, in[5] + 0xd62f105dL, 5);
	MD5STEP(F2(a,b,c), d, a, b, c, in[10] + 0x02441453L, 9);
	MD5STEP(F2(d,a,b), c, d, a, b, in[15] + 0xd8a1e681L, 14);
	MD5STEP(F2(c,d,a), b, c, d, a, in[4] + 0xe7d3fbc8L, 20);
	MD5STEP(F2(b,c,d), a, b, c, d, in[9] + 0x21e1cde6L, 5);
	MD5STEP(F2(a,b,c), d, a, b, c, in[14] + 0xc33707d6L, 9);
	MD5STEP(F2(d,a,b), c, d, a, b, in[3] + 0xf4d50d87L, 14);
	MD5STEP(F2(c,d,a), b, c, d, a, in[8] + 0x455a14edL, 20);
	MD5STEP(F2(b,c,d), a, b, c, d, in[13] + 0xa9e3e905L, 5);
	MD5STEP(F2(a,b,c), d, a, b, c, in[2] + 0xfcefa3f8L, 9);
	MD5STEP(F2(d,a,b), c, d, a, b, in[7] + 0x676f02d9L, 14);
	MD5STEP(F2(c,d,a), b, c, d, a, in[12] + 0x8d2a4c8aL, 20);

	MD5STEP(F3(b,c,d), a, b, c, d, in[5] + 0xfffa3942L, 4);
	MD5STEP(F3(a,b,c), d, a, b, c, in[8] + 0x8771f681L, 11);
	MD5STEP(F3(d,a,b), c, d, a, b, in[11] + 0x6d9d6122L, 16);
	MD5STEP(F3(c,d,a), b, c, d, a, in[14] + 0xfde5380cL, 23);
	MD5STEP(F3(b,c,d), a, b, c, d, in[1] + 0xa4beea44L, 4);
	MD5STEP(F3(a,b,c), d, a, b, c, in[4] + 0x4bdecfa9L, 11);
	MD5STEP(F3(d,a,b), c, d, a, b, in[7] + 0xf6bb4b60L, 16);
	MD5STEP(F3(c,d,a), b, c, d, a, in[10] + 0xbebfbc70L, 23);
	MD5STEP(F3(b,c,d), a, b, c, d, in[13] + 0x289b7ec6L, 4);
	MD5STEP(F3(a,b,c), d, a, b, c, in[0] + 0xeaa127faL, 11);
	MD5STEP(F3(d,a,b), c, d, a, b, in[3] + 0xd4ef3085L, 16);
	MD5STEP(F3(c,d,a), b, c, d, a, in[6] + 0x04881d05L, 23);
	MD5STEP(F3(b,c,d), a, b, c, d, in[9] + 0xd9d4d039L, 4);
	MD5STEP(F3(a,b,c), d, a, b, c, in[12] + 0xe6db99e5L, 11);
	MD5STEP(F3(d,a,b), c, d, a, b, in[15] + 0x1fa27cf8L, 16);
	MD5STEP(F3(c,d,a), b, c, d, a, in[2] + 0xc4ac5665L, 23);

	MD5STEP(F4(b,c,d), a, b, c, d, in[0] + 0xf4292244L, 6);
	MD5STEP(F4(a,b,c), d, a, b, c, in[7] + 0x432aff97L, 10);
	MD5STEP(F4(d,a,b), c, d, a, b, in[14] + 0xab9423a7L, 15);
	MD5STEP(F4(c,d,a), b, c, d, a, in[5] + 0xfc93a039L, 21);
	MD5STEP(F4(b,c,d), a, b, c, d, in[12] + 0x655b59c3L, 6);
	MD5STEP(F4(a,b,c), d, a, b, c, in[3] + 0x8f0ccc92L, 10);
	MD5STEP(F4(d,a,b), c, d, a, b, in[10] + 0xffeff47dL, 15);
	MD5STEP(F4(c,d,a), b, c, d, a, in[1] + 0x85845dd1L, 21);
	MD5STEP(F4(b,c,d), a, b, c, d, in[8] + 0x6fa87e4fL, 6);
	MD5STEP(F4(a,b,c), d, a, b, c, in[15] + 0xfe2ce6e0L, 10);
	MD5STEP(F4(d,a,b), c, d, a, b, in[6] + 0xa3014314L, 15);
	MD5STEP(F4(c,d,a), b, c, d, a, in[13] + 0x4e0811a1L, 21);
	MD5STEP(F4(b,c,d), a, b, c, d, in[4] + 0xf7537e82L, 6);
	MD5STEP(F4(a,b,c), d, a, b, c, in[11] + 0xbd3af235L, 10);
	MD5STEP(F4(d,a,b), c, d, a, b, in[2] + 0x2ad7d2bbL, 15);
	MD5STEP(F4(c,d,a), b, c, d, a, in[9] + 0xeb86d391L, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

#endif

using namespace UCOMMON_NAMESPACE;

#ifdef	MD5_MISSING
unsigned digest::md5(unsigned char *target, const char *str)
{
	return 0;
}
#endif

#ifdef	SHA1_MISSING
unsigned digest::sha1(unsigned char *target, const char *str)
{
	return 0;
}
#endif

#ifdef	RMD160_MISSING
unsigned digest::rmd160(unsigned char *target, const char *str)
{
	return 0;
}
#endif

#ifdef	MD5_GENERIC
unsigned digest::md5(unsigned char *digest, const char *str)
{
	MD5_CTX md5;

	if(!str)
		return 0;

	MD5Init(&md5);
	MD5Update(&md5, (unsigned char *)str, strlen(str));
	MD5Final(digest, &md5);
	return 16;
}
#endif

#ifdef	SHA1_GENERIC
unsigned digest::sha1(unsigned char *digest, const char *str)
{
	SHA_CTX sha1;

	if(!str)
		return 0;

	SHA1Init(&sha1);
	SHA1Update(&sha1, (unsigned char *)str, strlen(str));
	SHA1Final(digest, &sha1);
	return 20;
}
#endif

#ifdef	RMD160_GENERIC
unsigned digest::rmd160(unsigned char *digest, const char *str)
{
	RMD160_CTX rmd160;

	if(!str)
		return 0;

	RMD160Init(&rmd160);
	RMD160Update(&rmd160, (unsigned char *)str, strlen(str));
	RMD160Final(digest, &rmd160);
	return 20;
}
#endif

#ifdef	MD5_GCRYPT
unsigned digest::md5(unsigned char *digest, const char *str)
{
	gcry_md_hd_t md5;

	gcry_md_open(&md5, GCRY_MD_MD5, 0);
	if(!md5)
		return 0;

	gcry_md_enable(md5, GCRY_MD_MD5);
	gcry_md_write(md5, str, strlen(str));
	gcry_md_final(md5);
	unsigned char *ptr = gcry_md_read(md5, GCRY_MD_MD5);
	memcpy(digest, ptr, 16);
	digest[16] = 0;
	gcry_md_close(md5);
	return 16;
}	
#endif

#ifdef	SHA1_GCRYPT
unsigned digest::sha1(unsigned char *digest, const char *str)
{
	gcry_md_hd_t sha1;

	gcry_md_open(&sha1, GCRY_MD_SHA1, 0);
	if(!sha1)
		return 0;

	gcry_md_enable(sha1, GCRY_MD_SHA1);
	gcry_md_write(sha1, str, strlen(str));
	gcry_md_final(sha1);
	unsigned char *ptr = gcry_md_read(sha1, GCRY_MD_SHA1);
	memcpy(digest, ptr, 20);
	digest[20] = 0;
	gcry_md_close(sha1);
	return 20;
}	
#endif

#ifdef	RMD160_GCRYPT
unsigned digest::rmd160(unsigned char *digest, const char *str)
{
	gcry_md_hd_t rmd160;

	gcry_md_open(&rmd160, GCRY_MD_RMD160, 0);
	if(!rmd160)
		return 0;

	gcry_md_enable(rmd160, GCRY_MD_RMD160);
	gcry_md_write(rmd160, str, strlen(str));
	gcry_md_final(rmd160);
	unsigned char *ptr = gcry_md_read(rmd160, GCRY_MD_RMD160);
	memcpy(digest, ptr, 20);
	digest[20] = 0;
	gcry_md_close(rmd160);
	return 20;
}	
#endif

unsigned digest::md5(string &d, const char *s)
{
	char strbuf[33];
	unsigned char digbuf[16];
	unsigned idx = 0;

	if(!s)
		s = *d;

	if(!md5(digbuf, s)) {
		d.set("");
		return 0;
	}

	while(idx < 16) {
		snprintf(strbuf + (idx * 2), 3, "%2.2x", digbuf[idx]);
		++idx;
	}
	strbuf[idx * 2] = 0;
	if(d.size() < 32)
		d ^= strbuf;
	else
		d = strbuf;
	return 16;
}
	
unsigned digest::sha1(string &d, const char *s)
{
	char strbuf[41];
	unsigned char digbuf[20];
	unsigned idx = 0;

	if(!s)
		s = *d;

	if(!sha1(digbuf, s)) {
		d.set("");
		return 0;
	}

	while(idx < 20) {
		snprintf(strbuf + (idx * 2), 3, "%2.2x", digbuf[idx]);
		++idx;
	}
	strbuf[idx * 2] = 0;
	if(d.size() < 40)
		d ^= strbuf;
	else
		d = strbuf;
	return 20;
}

unsigned digest::rmd160(string &d, const char *s)
{
	char strbuf[41];
	unsigned char digbuf[20];
	unsigned idx = 0;

	if(!s)
		s = *d;

	if(!rmd160(digbuf, s)) {
		d.set("");
		return 0;
	}

	while(idx < 20) {
		snprintf(strbuf + (idx * 2), 3, "%2.2x", digbuf[idx]);
		++idx;
	}
	strbuf[idx * 2] = 0;
	if(d.size() < 40)
		d ^= strbuf;
	else
		d = strbuf;
	return 20;
}

