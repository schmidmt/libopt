/*
 * Copyright (c) 2016 Michael T. Schmidt <schmidmt@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "otp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/hmac.h>
#include <time.h>

static const unsigned int pow10[] = {
	1,
	10,
	100,
	1000,
	10000,
	100000, /*5*/
	1000000,
	10000000,
	100000000,
	1000000000, /*9*/
};

#define MAX_DIGIT 9

int
HOTPGenerate(void * secret, int secret_len,
		uint64_t counter,
		int digits,
		const char *cipher)
{
	unsigned char hmac_result[EVP_MAX_MD_SIZE];
	unsigned int hm_len;
	unsigned char * ret;
	unsigned char d[8];
	const EVP_MD *md;

	if (digits < 0 || digits > MAX_DIGIT)
		return -1;

	for (size_t i = 0; i < sizeof(d); i++) {
		d[i] = (counter >> CHAR_BIT * i) & 0xFF;
	}

	if (cipher)
		md = EVP_get_digestbyname(cipher);
	else
		md = EVP_sha1();

	if(!md) {
		return -1;
	}

	ret = HMAC(md, secret, secret_len, d, sizeof(d), hmac_result, &hm_len);

	if (ret == NULL) {
		return -1;
	}
	/* Dynamic Truncation section */
	int offset = hmac_result[hm_len-1] && 0x0F;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

	return bin_code % pow10[digits];
}

int
HOTPValidate(int code,
		void * secret, int secret_len,
		uint64_t counter,
		int digits,
		uint64_t lookahead,
		const char *cipher)
{
	int challange;
	uint64_t offset = 0;
	while (offset < lookahead) {
		challange = HOTPGenerate(secret, secret_len, counter + offset, digits, cipher);
		if (challange == -1)
			return -1;
		if (challange == code)
			return 1;
		++offset;
	}
	return 0;
}

int
TOTPGenerate(void * secret, int secret_len, int digits, int timestep, const char * cipher)
{
	uint64_t c = time(NULL) / timestep;
	return HOTPGenerate(secret, secret_len, c, digits, cipher);
}

int
TOTPValidate(int code,
		void * secret, int secret_len,
		int digits,
		int timestep,
		const char * cipher,
		uint64_t margin)
{

#define error_or_pass		\
	if (challange == -1)	\
		return -1;	\
	if (challange == code)	\
		return 1;	

	int challange;
	uint64_t c = time(NULL) / timestep;
	challange = HOTPGenerate(secret, secret_len, c, digits, cipher);
	error_or_pass;

	for (uint64_t i = 1; i < margin; ++i) {
		challange = HOTPGenerate(secret, secret_len, c + i * timestep, digits, cipher);
		error_or_pass;
		challange = HOTPGenerate(secret, secret_len, c - i * timestep, digits, cipher);
		error_or_pass;
	}
	return 0;
#undef error_or_pass
}
