#include <memory.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "pkcs11.h"
#include "config.h"

#ifdef ENABLE_PKCS11
    #include PKCS11_HEADER
#endif

#define SLOT_COUNT 128
#define LABEL_SIZE 32

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static CK_BBOOL CTRUE  = TRUE;
//static CK_BBOOL CFALSE = FALSE;

static int find_the_token(CK_SLOT_ID *slot) {
    CK_RV ret;
    CK_SLOT_ID slots[SLOT_COUNT];

    /* get slot list: */
    unsigned long count = SLOT_COUNT;
    if ((ret = C_GetSlotList(FALSE, slots, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    /* find the desired token: */
    int token_found = 0;
    for (unsigned long i = 0; i < count; i++) {
        CK_TOKEN_INFO token;
        if ((ret = C_GetTokenInfo(slots[i], &token)) != CKR_OK) {
            OPENSSL_PUT_ERROR(PKCS11,ret);
            return 0;
        }
        if (memcmp(PKCS11_TOKEN_LABEL, token.label, LABEL_SIZE) == 0) {
            token_found = 1;
            *slot = slots[i];
            break;
        }
    }
    if (!token_found) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_LABEL_NOT_FOUND);
        return 0;
    }
    return 1;
}

static int fill_rsa(RSA* rsa, CK_SESSION_HANDLE* session, CK_OBJECT_HANDLE *private, CK_ULONG bits) {
    CK_RV ret;
    CK_ULONG bytes = bits / 8;
    CK_BYTE modulus[bytes];
    CK_BYTE prime1[bytes];
    CK_BYTE prime2[bytes];
    CK_BYTE pub_exp[bytes];
    CK_BYTE priv_exp[bytes];
    CK_BYTE exp1[bytes];
    CK_BYTE exp2[bytes];
    CK_BYTE inverse[bytes];

    CK_KEY_TYPE key_type = CKK_RSA;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE templ[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
            { CKA_MODULUS, modulus, sizeof(modulus)},
            { CKA_PUBLIC_EXPONENT, pub_exp, sizeof(pub_exp) },
            { CKA_PRIVATE_EXPONENT, priv_exp, sizeof(priv_exp) },
            { CKA_PRIME_1, prime1, sizeof(prime1) },
            { CKA_PRIME_2, prime2, sizeof(prime2) },
            { CKA_EXPONENT_1, exp1, sizeof(exp1) },
            { CKA_EXPONENT_2, exp2, sizeof(exp2) },
            { CKA_COEFFICIENT, inverse, sizeof(inverse) }
    };

    if ((ret = C_GetAttributeValue(*session, *private, templ, ARRAY_SIZE(templ))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11, ret);
        return 0;
    }

    BIGNUM *e, *n, *d, *p1, *p2, *dmp1, *dmq1, *iqmp;
    BN_dec2bn(&n, (char*)modulus);
    BN_dec2bn(&e, (char*)pub_exp);
    BN_dec2bn(&d, (char*)priv_exp);
    BN_dec2bn(&p1, (char*)prime1);
    BN_dec2bn(&p2, (char*)prime2);
    BN_dec2bn(&dmp1, (char*)exp1);
    BN_dec2bn(&dmq1, (char*)exp2);
    BN_dec2bn(&iqmp, (char*)inverse);

    rsa->e = e;
    rsa->n = n;
    rsa->d = d;
    rsa->p = p1;
    rsa->q = p2;
    rsa->dmp1 = dmp1;
    rsa->dmq1 = dmq1;
    rsa->iqmp = iqmp;

    return 0;
}

int PKCS11_RSA_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e_value) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (!rsa || !e_value) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_NULL_PARAMETER);
        return 0;
    }

    CK_RV ret;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot;

    CK_MECHANISM mech;
    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    if (!find_the_token(&slot)) {
        return 0;
    }

    if ((ret = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION,
                             NULL_PTR, NULL_PTR, &session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    /*if ((ret = C_Login(session, CKU_USER, PKCS11_PIN, ARRAY_SIZE(PKCS11_PIN))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }*/

    CK_ULONG ck_bits = bits;
    CK_BYTE_PTR ck_exponent = (unsigned char*)BN_bn2dec(e_value);
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE RSA_PUB_TEMPLATE[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_MODULUS_BITS, &ck_bits, sizeof(ck_bits) },
            { CKA_ENCRYPT, &CTRUE, sizeof(CTRUE) },
            { CKA_VERIFY, &CTRUE, sizeof(CTRUE) },
            { CKA_PUBLIC_EXPONENT, ck_exponent, BN_num_bytes(e_value) }
    };

    class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE RSA_PRIV_TEMPLATE[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_SENSITIVE, &CTRUE, sizeof(CTRUE) },
            { CKA_DECRYPT, &CTRUE, sizeof(CTRUE)  },
            { CKA_SIGN, &CTRUE, sizeof(CTRUE)  }
    };

    CK_OBJECT_HANDLE priv_key, pub_key;

    if ((ret = C_GenerateKeyPair(session, &mech,
                            RSA_PUB_TEMPLATE, ARRAY_SIZE(RSA_PUB_TEMPLATE),
                            RSA_PRIV_TEMPLATE, ARRAY_SIZE(RSA_PRIV_TEMPLATE),
                            &pub_key, &priv_key)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if (!fill_rsa(rsa, &session, &priv_key, bits)) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_FILL_RSA_ERR);
        return 0;
    }

    return 1;
}

int PKCS11_RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    CK_RV ret;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot;

    if (!find_the_token(&slot)) {
        return 0;
    }

    if ((ret = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION,
                             NULL_PTR, NULL_PTR, &session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    /*if ((ret = C_Login(session, CKU_USER, PKCS11_PIN, ARRAY_SIZE(PKCS11_PIN))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
    ret = C_EncryptInit(session, &mech, pubkey);
    if (ret != CKR_OK) {
        fprintf(stderr, "ERROR: C_EncryptInit(): %lu\n", ret);
        return 1;
    }

    if ((ret = C_Encrypt(session, (unsigned char*)in, in_len, out, out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }*/
    return 0;
}
