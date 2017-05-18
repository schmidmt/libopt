/* -*- mode: c; c-file-style: "openbsd" -*- */
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

#ifndef _OTP_H
#define _OTP_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdlib.h>
#include <inttypes.h>

/**
 * @brief Generate a HMAC One Time Password (HOTP)
 *
 * This generates a HOTP code ([RFC 6238](https://tools.ietf.org/html/rfc6238)).
 *
 * # Errors
 * If any error occures, the return value will be less than zero.
 *
 * @param secret Shared secret used to authenticate.
 * @param secret_len Length of secret key.
 * @param counter Counter representing number of authentications or some other monotonically increasing number.
 * @param digits Number of digits to return
 * @param cipher Name of cipher to use (NULL = SHA1)
 * @returns HOTP code
 */
int
HOTPGenerate(void * secret, int secret_len, uint64_t counter, int digits, const char * cipher);

int
HOTPValidate(int code, void * secret, int secret_len, uint64_t counter, int digits, uint64_t lookahead, const char * cipher);

int
TOTPGenerate(void * secret, int secret_len, int digits, int timestep, const char * cipher)

int
TOTPValidate(int code, void * secret, int secret_len, int digits, int timestep, const char * cipher, uint64_t margin);

#endif /*_OTP_H */
