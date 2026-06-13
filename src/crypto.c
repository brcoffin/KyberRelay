#include "crypto.h"

#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>
#include <sodium.h>

/* Map our param enum to liboqs algorithm names */
static const char *kem_alg_name(KyberParamSet p)
{
    switch (p) {
    case MLKEM_512:  return OQS_KEM_alg_ml_kem_512;
    case MLKEM_768:  return OQS_KEM_alg_ml_kem_768;
    case MLKEM_1024: return OQS_KEM_alg_ml_kem_1024;
    default:         return NULL;
    }
}

/* ---------- Secure wipe ---------- */

void kyber_secure_zero(void *ptr, size_t len)
{
    sodium_memzero(ptr, len);
}

/* ---------- Error strings ---------- */

const char *kyber_error_str(KyberError err)
{
    switch (err) {
    case KYBER_OK:                return "Success";
    case KYBER_ERR_ALLOC:        return "Memory allocation failed";
    case KYBER_ERR_IO:           return "I/O error";
    case KYBER_ERR_CRYPTO:       return "Cryptographic operation failed";
    case KYBER_ERR_COMPRESS:     return "Compression/decompression failed";
    case KYBER_ERR_FORMAT:       return "Invalid archive format";
    case KYBER_ERR_TAMPERED:     return "Archive integrity check failed";
    case KYBER_ERR_WRONG_KEY:    return "Wrong key or corrupted data";
    case KYBER_ERR_KEY_NOT_FOUND:return "Key not found";
    case KYBER_ERR_INVALID_PARAM:return "Invalid parameter";
    default:                     return "Unknown error";
    }
}

/* ---------- ML-KEM key generation ---------- */

KyberError kyber_keygen(KyberParamSet param, KyberKeypair *kp)
{
    const char *alg = kem_alg_name(param);
    if (!alg) return KYBER_ERR_INVALID_PARAM;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return KYBER_ERR_CRYPTO;

    kp->param = param;
    kp->public_key_len = kem->length_public_key;
    kp->secret_key_len = kem->length_secret_key;
    kp->public_key = malloc(kp->public_key_len);
    /* Plain malloc (wiped via kyber_secure_zero on free) so ownership can be
     * transferred into the keystore, which frees secret keys the same way. */
    kp->secret_key = malloc(kp->secret_key_len);

    if (!kp->public_key || !kp->secret_key) {
        OQS_KEM_free(kem);
        kyber_keypair_free(kp);
        return KYBER_ERR_ALLOC;
    }

    if (OQS_KEM_keypair(kem, kp->public_key, kp->secret_key) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        kyber_keypair_free(kp);
        return KYBER_ERR_CRYPTO;
    }

    OQS_KEM_free(kem);
    return KYBER_OK;
}

/* ---------- ML-KEM encapsulation ---------- */

KyberError kyber_encaps(const uint8_t *pubkey, size_t pubkey_len,
                        KyberParamSet param,
                        uint8_t *ciphertext, size_t *ct_len,
                        uint8_t *shared_secret)
{
    const char *alg = kem_alg_name(param);
    if (!alg) return KYBER_ERR_INVALID_PARAM;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return KYBER_ERR_CRYPTO;

    if (pubkey_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        return KYBER_ERR_INVALID_PARAM;
    }

    *ct_len = kem->length_ciphertext;

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, pubkey) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return KYBER_ERR_CRYPTO;
    }

    OQS_KEM_free(kem);
    return KYBER_OK;
}

/* ---------- ML-KEM decapsulation ---------- */

KyberError kyber_decaps(const uint8_t *seckey, size_t seckey_len,
                        KyberParamSet param,
                        const uint8_t *ciphertext, size_t ct_len,
                        uint8_t *shared_secret)
{
    const char *alg = kem_alg_name(param);
    if (!alg) return KYBER_ERR_INVALID_PARAM;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) return KYBER_ERR_CRYPTO;

    if (seckey_len != kem->length_secret_key ||
        ct_len != kem->length_ciphertext) {
        OQS_KEM_free(kem);
        return KYBER_ERR_INVALID_PARAM;
    }

    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, seckey) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return KYBER_ERR_CRYPTO;
    }

    OQS_KEM_free(kem);
    return KYBER_OK;
}

/* ---------- Keypair cleanup ---------- */

void kyber_keypair_free(KyberKeypair *kp)
{
    if (!kp) return;
    if (kp->secret_key) {
        kyber_secure_zero(kp->secret_key, kp->secret_key_len);
        free(kp->secret_key);
    }
    if (kp->public_key) {
        free(kp->public_key);
    }
    memset(kp, 0, sizeof(*kp));
}

/* ---------- Public-key fingerprint ---------- */

void kyber_fingerprint(const uint8_t *pubkey, size_t pubkey_len,
                       char *out, size_t out_size)
{
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!pubkey || pubkey_len == 0) return;

    /* 10-byte BLAKE2b digest -> 80 bits, ample for manual comparison. */
    unsigned char h[10];
    crypto_generichash(h, sizeof(h), pubkey, pubkey_len, NULL, 0);

    static const char hexd[] = "0123456789ABCDEF";
    char buf[32];
    size_t j = 0;
    for (size_t i = 0; i < sizeof(h); i++) {
        if (i > 0 && (i % 2) == 0) buf[j++] = ' '; /* group every 2 bytes */
        buf[j++] = hexd[(h[i] >> 4) & 0xF];
        buf[j++] = hexd[h[i] & 0xF];
    }
    buf[j] = '\0';

    strncpy(out, buf, out_size - 1);
    out[out_size - 1] = '\0';
}

/* ---------- KDF (BLAKE2b via libsodium) ---------- */

KyberError kyber_kdf(const uint8_t *shared_secret,
                     const uint8_t *context, size_t context_len,
                     uint64_t subkey_id,
                     uint8_t *key_out, uint8_t *nonce_out)
{
    /*
     * Use BLAKE2b to derive key material from the KEM shared secret.
     * We derive key + nonce in one shot using crypto_generichash with
     * the subkey_id mixed into the personal parameter.
     */
    uint8_t okm[KYBER_SYM_KEY_LEN + KYBER_SYM_NONCE_LEN];

    /* Use BLAKE2b keyed hash: shared_secret as key, context+subkey_id as message */
    uint8_t msg[256];
    size_t msg_len = 0;

    /* Pack subkey_id into message */
    memcpy(msg, &subkey_id, sizeof(subkey_id));
    msg_len += sizeof(subkey_id);

    /* Append context */
    if (context && context_len > 0) {
        size_t copy_len = context_len < sizeof(msg) - msg_len
                        ? context_len : sizeof(msg) - msg_len;
        memcpy(msg + msg_len, context, copy_len);
        msg_len += copy_len;
    }

    if (crypto_generichash(okm, sizeof(okm),
                           msg, msg_len,
                           shared_secret, KYBER_SHARED_SECRET_LEN) != 0) {
        return KYBER_ERR_CRYPTO;
    }

    memcpy(key_out, okm, KYBER_SYM_KEY_LEN);
    memcpy(nonce_out, okm + KYBER_SYM_KEY_LEN, KYBER_SYM_NONCE_LEN);
    sodium_memzero(okm, sizeof(okm));

    return KYBER_OK;
}

/* ---------- AES-256-GCM availability check ---------- */

bool kyber_aes256gcm_available(void)
{
    return crypto_aead_aes256gcm_is_available() != 0;
}

/* ---------- AES-256-GCM encrypt (via libsodium) ---------- */

KyberError kyber_sym_encrypt(const uint8_t *key, const uint8_t *nonce,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t len,
                             uint8_t *ciphertext, uint8_t *tag)
{
    if (!kyber_aes256gcm_available()) return KYBER_ERR_CRYPTO;

    /*
     * libsodium's AEAD outputs ciphertext || tag in one buffer.
     * We split them for our archive format.
     */
    unsigned long long combined_len;
    uint8_t *combined = malloc(len + crypto_aead_aes256gcm_ABYTES);
    if (!combined) return KYBER_ERR_ALLOC;

    if (crypto_aead_aes256gcm_encrypt(
            combined, &combined_len,
            plaintext, (unsigned long long)len,
            aad, (unsigned long long)aad_len,
            NULL, nonce, key) != 0) {
        free(combined);
        return KYBER_ERR_CRYPTO;
    }

    /* Split: first `len` bytes are ciphertext, last ABYTES are tag */
    memcpy(ciphertext, combined, len);
    memcpy(tag, combined + len, crypto_aead_aes256gcm_ABYTES);
    free(combined);

    return KYBER_OK;
}

/* ---------- AES-256-GCM decrypt (via libsodium) ---------- */

KyberError kyber_sym_decrypt(const uint8_t *key, const uint8_t *nonce,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t len,
                             const uint8_t *tag,
                             uint8_t *plaintext)
{
    if (!kyber_aes256gcm_available()) return KYBER_ERR_CRYPTO;

    /* Reconstruct combined buffer: ciphertext || tag */
    size_t combined_len = len + crypto_aead_aes256gcm_ABYTES;
    uint8_t *combined = malloc(combined_len);
    if (!combined) return KYBER_ERR_ALLOC;

    memcpy(combined, ciphertext, len);
    memcpy(combined + len, tag, crypto_aead_aes256gcm_ABYTES);

    unsigned long long decrypted_len;
    if (crypto_aead_aes256gcm_decrypt(
            plaintext, &decrypted_len,
            NULL,
            combined, (unsigned long long)combined_len,
            aad, (unsigned long long)aad_len,
            nonce, key) != 0) {
        free(combined);
        return KYBER_ERR_TAMPERED;
    }

    free(combined);
    return KYBER_OK;
}
