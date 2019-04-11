/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_PKCS11_PKCS11_H
#define OPENSSL_HEADER_PKCS11_PKCS11_H

#include <openssl/base.h>

/*#if !defined(OPENSSL_WINDOWS)
#if defined(OPENSSL_PNACL)
// newlib uses u_short in socket.h without defining it.
typedef unsigned short u_short;
#endif
#include <sys/types.h>
#include <sys/socket.h>
#else
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <winsock2.h>
OPENSSL_MSVC_PRAGMA(warning(pop))
typedef int socklen_t;
#endif*/

#if defined(__cplusplus)
extern "C" {
#endif

// RSA functions

int PKCS11_RSA_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e_value);
int PKCS11_RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int PKCS11_RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int PKCS11_RSA_sign(int hash_nid, const uint8_t *in, unsigned int in_len, uint8_t *out, unsigned int *out_len, RSA *rsa);

// ECDSA functions

// int PKCS11_EC_KEY_generate_key(EC_KEY *key);

// Error codes

#define PKCS11_LABEL_NOT_FOUND 500
#define PKCS11_FILL_RSA_ERR 501
#define PKCS11_NULL_PARAMETER 502
#define PKCS11_NOT_ENABLED 503
#define PKCS11_UNKNOWN_PADDING 504
#define PKCS11_OBJECT_NOT_FOUND 505
#define PKCS11_UNKNOWN_HASH 506

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_PKCS11_PKCS11_H
