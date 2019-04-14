/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "../crypto/pkcs11/pkcs11.h"

#define CHECK(what, msg) if(!(what)) { printf("Failed to %s.\n", msg); }

extern "C" {

static void hexdump(uint8_t *buf, size_t howmuch)
{
	size_t byte;
	for(byte = 0; byte < howmuch; byte++)
	{
		printf("%02hhX ", buf[byte]);
		if((byte > 0) && !(byte % 64)) printf("\n");
	}
	if(byte % 64) printf("\n");
}

int main(int argc, char **argv)
{
	printf("PKCS#11 tests started.\n\n");

	PKCS11_init();

	printf("Generating RSA key...\n");
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	CHECK(BN_set_word(e, RSA_F4), "set the public exponent");
	CHECK(PKCS11_RSA_generate_key_ex(rsa, 2048, e), "generate the RSA keys");
	CHECK(PEM_write_bio_RSAPublicKey(bio, rsa), "write the public RSA key into stdout.");

	printf("\nAttempting to encrypt the text 'some junk text' with this key...\n");
	
	char msg[] = "some junk text";
	char *out = (char *) malloc(1024);
	size_t outlen = 1024;
	CHECK(PKCS11_RSA_encrypt(rsa, &outlen, (uint8_t *) out, 1024, (uint8_t *) msg, 14, RSA_PKCS1_OAEP_PADDING), "encode message with RSA");

	hexdump((uint8_t *) out, outlen);

	PKCS11_kill();
	return 0;
}

}
