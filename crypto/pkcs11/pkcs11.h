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
#include "config.h"

#ifdef ENABLE_PKCS11
#include PKCS11_HEADER
#include "../fipsmodule/ec/internal.h"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// Init & shutdown

typedef CK_SESSION_HANDLE PKCS11_session;
int PKCS11_init(void);
int PKCS11_kill(void);

int PKCS11_login(PKCS11_session *session);
int PKCS11_logout(PKCS11_session session);

// RSA functions

int PKCS11_RSA_generate_key_ex(PKCS11_session session, RSA *rsa, int bits, const BIGNUM *e_value);
int PKCS11_RSA_encrypt(PKCS11_session session, RSA *rsa, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int PKCS11_RSA_decrypt(PKCS11_session session, RSA *rsa, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int PKCS11_RSA_sign(PKCS11_session session, RSA *rsa, int hash_nid, uint8_t *out, unsigned int *out_len, const uint8_t *in, unsigned int in_len);

// ECDSA functions

int PKCS11_EC_KEY_generate_key(PKCS11_session session, EC_KEY *key);
int PKCS11_ECDSA_sign(PKCS11_session session, const EC_KEY *key, const uint8_t *digest, size_t digest_len, uint8_t *sig, unsigned int *sig_len);
int PKCS11_ECDSA_verify(PKCS11_session session, const EC_KEY *key, const uint8_t *digest, size_t digest_len, const uint8_t *sig, size_t sig_len);

// Error codes

#define PKCS11_LABEL_NOT_FOUND 500
#define PKCS11_FILL_RSA_ERR 501
#define PKCS11_NULL_PARAMETER 502
#define PKCS11_NOT_ENABLED 503
#define PKCS11_UNKNOWN_PADDING 504
#define PKCS11_OBJECT_NOT_FOUND 505
#define PKCS11_UNKNOWN_HASH 506
#define PKCS11_EXTRACT_ASN1_FAIL 507
#define PKCS11_FILL_EC_ERR 508
#define PKCS11_INVALID_ENCODING 509
#define PKCS11_OUT_BUFFER_TOO_SMALL 510

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_PKCS11_PKCS11_H