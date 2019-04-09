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
static CK_BBOOL CFALSE = FALSE;

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

static int get_session(CK_SESSION_HANDLE* session) {
    CK_RV ret;
    CK_SLOT_ID slot;

    if (!find_the_token(&slot)) {
        return 0;
    }

    if ((ret = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION,
                             NULL_PTR, NULL_PTR, session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }

    if ((ret = C_Login(session, CKU_USER, PKCS11_TOKEN_PIN, ARRAY_SIZE(PKCS11_TOKEN_PIN))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 0;
    }
    return 1;
}

static int fill_rsa_pub(RSA *rsa, CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *public, CK_ULONG bits) {
    CK_RV ret;
    CK_ULONG bytes = bits / 8;
    CK_BYTE modulus[bytes];
    CK_BYTE exp[bytes];

    CK_KEY_TYPE key_type = CKK_RSA;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE templ[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
            { CKA_MODULUS, modulus, sizeof(modulus)},
            { CKA_PUBLIC_EXPONENT, exp, sizeof(exp) }
    };

    if ((ret = C_GetAttributeValue(*session, *public, templ, ARRAY_SIZE(templ))) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11, ret);
        return 0;
    }

    BIGNUM *e, *n;
    BN_dec2bn(&n, (char*)modulus);
    BN_dec2bn(&e, (char*)exp);
    rsa->e = e;
    rsa->n = n;

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

    get_session(&session);
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

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
            { CKA_EXTRACTABLE, &CFALSE, sizeof(CFALSE) },
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

    if (!fill_rsa_pub(rsa, &session, &pub_key, bits)) {
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
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_VALUE_MISSING);
        return 0;
    }

    if (max_out < RSA_size(rsa)) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    CK_RV ret;
    CK_SESSION_HANDLE session;

    get_session(&session);

    CK_MECHANISM_TYPE type;
    switch (padding) {
        case RSA_PKCS1_PADDING : type = CKM_RSA_PKCS; break;
        case RSA_NO_PADDING : type = CKM_RSA_X_509; break;
        case RSA_PKCS1_OAEP_PADDING : type = CKM_RSA_PKCS_OAEP; break;
        case RSA_PKCS1_PSS_PADDING : type = CKM_RSA_PKCS_PSS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_PADDING); return 0;
    }
    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_BYTE_PTR modulus = (unsigned char*)BN_bn2dec(rsa->n);
    CK_BYTE_PTR exponent = (unsigned char*)BN_bn2dec(rsa->e);
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE templ[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_MODULUS, modulus, BN_num_bytes(rsa->n) },
            { CKA_ENCRYPT, &CTRUE, sizeof(CTRUE) },
            { CKA_VERIFY, &CTRUE, sizeof(CTRUE) },
            { CKA_PUBLIC_EXPONENT, exponent, BN_num_bytes(rsa->e) }
    };
    CK_OBJECT_HANDLE public;

    if ((ret = C_FindObjectsInit(session, templ, 6)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    CK_ULONG count;
    if ((ret = C_FindObjects(session, &public, 1, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if (count < 1) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_OBJECT_NOT_FOUND);
        return 1;
    }

    if ((ret = C_FindObjectsFinal(session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if ((ret = C_EncryptInit(session, &mech, public)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if ((ret = C_Encrypt(session, (unsigned char*)in, in_len, out, out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }
    return 0;
}

int PKCS11_RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding) {
#ifndef ENABLE_PKCS11
    OPENSSL_PUT_ERROR(PKCS11,PKCS11_NOT_ENABLED);
    return 0;
#endif
    if (rsa->n == NULL || rsa->e == NULL) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_VALUE_MISSING);
        return 0;
    }

    if (max_out < RSA_size(rsa)) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    CK_RV ret;
    CK_SESSION_HANDLE session;

    get_session(&session);

    CK_MECHANISM_TYPE type;
    switch (padding) {
        case RSA_PKCS1_PADDING : type = CKM_RSA_PKCS; break;
        case RSA_NO_PADDING : type = CKM_RSA_X_509; break;
        case RSA_PKCS1_OAEP_PADDING : type = CKM_RSA_PKCS_OAEP; break;
        case RSA_PKCS1_PSS_PADDING : type = CKM_RSA_PKCS_PSS; break;
        default : OPENSSL_PUT_ERROR(PKCS11, PKCS11_UNKNOWN_PADDING); return 0;
    }
    CK_MECHANISM mech = { type, NULL_PTR, 0 };

    CK_BYTE_PTR modulus = (unsigned char*)BN_bn2dec(rsa->n);
    CK_BYTE_PTR exponent = (unsigned char*)BN_bn2dec(rsa->e);
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE templ[] = {
            { CKA_CLASS, &class, sizeof(class) },
            { CKA_TOKEN, &CTRUE, sizeof(CTRUE) },
            { CKA_MODULUS, modulus, BN_num_bytes(rsa->n) },
            { CKA_DECRYPT, &CTRUE, sizeof(CTRUE) },
            { CKA_PUBLIC_EXPONENT, exponent, BN_num_bytes(rsa->e) }
    };
    CK_OBJECT_HANDLE private;

    if ((ret = C_FindObjectsInit(session, templ, 6)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    CK_ULONG count;
    if ((ret = C_FindObjects(session, &private, 1, &count)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if (count < 1) {
        OPENSSL_PUT_ERROR(PKCS11,PKCS11_OBJECT_NOT_FOUND);
        return 1;
    }

    if ((ret = C_FindObjectsFinal(session)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if ((ret = C_DecryptInit(session, &mech, private)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }

    if ((ret = C_Decrypt(session, (unsigned char*)in, in_len, out, out_len)) != CKR_OK) {
        OPENSSL_PUT_ERROR(PKCS11,ret);
        return 1;
    }
    return 0;
}
