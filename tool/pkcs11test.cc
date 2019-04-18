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
#include <openssl/ec_key.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "../crypto/pkcs11/pkcs11.h"
#include "../crypto/pkcs11/config.h"

#define CHECK(what, msg) if(!(what)) { printf("Failed to %s.\n", msg); ERR_print_errors_fp(stderr); exit(1); }

extern "C" {

static void hexdump(uint8_t *buf, size_t howmuch)
{
	for(size_t byte = 0; byte < howmuch; byte++)
	{
		if((byte > 0) && !(byte % 32)) printf("\n");
		printf("%02hhX ", buf[byte]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	printf("PKCS#11 tests started.\n\n");

	PKCS11_init();
	CK_SESSION_HANDLE session;

	CHECK(PKCS11_login(&session, PKCS11_TOKEN_LABEL, (unsigned char *) PKCS11_TOKEN_PIN, strlen(PKCS11_TOKEN_PIN)), "log in");

	printf("Generating RSA key...\n");
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	CHECK(BN_set_word(e, RSA_F4), "set the public exponent");
	CHECK(PKCS11_RSA_generate_key_ex(session, rsa, 2048, e), "generate the RSA keys");
	CHECK(PEM_write_bio_RSAPublicKey(bio, rsa), "write the public RSA key into stdout.");

	printf("\nAttempting to encrypt the text 'some junk text' with this key...\n");
	
	char msg[] = "some junk text";
	uint8_t *encrypted = (uint8_t *) malloc(1024);
	size_t enclen = 1024;
	CHECK(PKCS11_RSA_encrypt(session, rsa, encrypted, &enclen, 1024, (uint8_t *) msg, 14, RSA_PKCS1_PADDING), "encode message with RSA");

	hexdump(encrypted, enclen);

	printf("\nAttempting to decrypt it back...\n");

	uint8_t *decrypted = (uint8_t *) malloc(1024);
	size_t declen = 1024;
	CHECK(PKCS11_RSA_decrypt(session, rsa, decrypted, &declen, 1024, encrypted, enclen, RSA_PKCS1_PADDING), "decode message with RSA");

	hexdump(decrypted, declen);

	printf("\nAttempting to sign 'some junk text' with this key...\n");

	uint8_t *signature = (uint8_t *) malloc(1024);
	size_t siglen = 1024;
	CHECK(PKCS11_RSA_sign(session, rsa, NID_sha512, signature, &siglen, (uint8_t *) msg, 14), "signing message with RSA.");

	hexdump(signature, siglen);

	printf("\nAttempting to verify the signature...\n");
	int ok;
	CHECK(PKCS11_RSA_verify(session, rsa, NID_sha512, (uint8_t *) msg, 14, signature, siglen, &ok), "verifying RSA signature.");
	printf("The signature is %svalid.\n", ok ? "" : "in");

	printf("\nAttempting to verify the signature, but with a modified text...\n");
	memcpy(msg + 5, "crap", 4);
	printf("Modified message: '%s'\n", msg);
	CHECK(PKCS11_RSA_verify(session, rsa, NID_sha512, (uint8_t *) msg, 14, signature, siglen, &ok), "verifying RSA signature.");
	printf("The signature is %svalid.\n", ok ? "" : "in");


	printf("\nAttempting to generate ECDSA key...\n");
	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp521r1);
	CHECK(PKCS11_EC_KEY_generate_key(session, ec), "generate an ECC key");
	CHECK(EC_KEY_check_key(ec), "pass sanity check on the generated key");
	CHECK(PEM_write_bio_EC_PUBKEY(bio, ec), "write the ECC key to stdout");

	free(encrypted);
	free(decrypted);
	free(signature);
	RSA_free(rsa);
	BN_free(e);
	BIO_free(bio);
	EC_KEY_free(ec);
	PKCS11_logout(session);
	PKCS11_kill();
	return 0;
}

}
