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
#include <iostream>

#include "internal.h"
#include "../crypto/pkcs11/pkcs11.h"


static const struct argument kArguments[] = {
    {
     "-bits", kOptionalArgument,
     "The number of bits in the modulus (default: 2048)",
    },
    {
     "", kOptionalArgument, "",
    },
};

bool GenerateRSAKeyPKCS11(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  unsigned bits;
  if (!GetUnsigned(&bits, "-bits", 2048, args_map)) {
    PrintUsage(kArguments);
    return false;
  }

  bssl::UniquePtr<RSA> rsa(RSA_new());
  bssl::UniquePtr<BIGNUM> e(BN_new());
  bssl::UniquePtr<BIO> bio(BIO_new_fp(stdout, BIO_NOCLOSE));
  PKCS11_session session;

  if (!PKCS11_init() ||
      !PKCS11_login(&session) ||
      !BN_set_word(e.get(), RSA_F4) ||
      !PKCS11_RSA_generate_key_ex(session, rsa.get(), bits, e.get()) ||
      !PEM_write_bio_RSAPublicKey(bio.get(), rsa.get())) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  PKCS11_logout(session);
  PKCS11_kill();
  return true;
}
