#ifndef KYBER_CRYPTO_H
#define KYBER_CRYPTO_H

#include "kyber_common.h"

/* Key sizes vary by parameter set; these are max sizes */
#define KYBER_MAX_PUBKEY_LEN   1568  /* ML-KEM-1024 public key */
#define KYBER_MAX_SECKEY_LEN   3168  /* ML-KEM-1024 secret key */
#define KYBER_MAX_CIPHERTEXT   1568  /* ML-KEM-1024 ciphertext */
#define KYBER_SHARED_SECRET_LEN  32  /* All parameter sets */

#define KYBER_SYM_KEY_LEN       32   /* AES-256-GCM key */
#define KYBER_SYM_NONCE_LEN     12   /* AES-256-GCM nonce */
#define KYBER_SYM_TAG_LEN       16   /* GCM auth tag */

/* ML-KEM keypair */
typedef struct {
    KyberParamSet param;
    uint8_t      *public_key;
    size_t        public_key_len;
    uint8_t      *secret_key;
    size_t        secret_key_len;
} KyberKeypair;

/* --- ML-KEM operations --- */

/* Generate a new ML-KEM keypair */
KyberError kyber_keygen(KyberParamSet param, KyberKeypair *kp);

/* Encapsulate: produce ciphertext + shared secret from a public key */
KyberError kyber_encaps(const uint8_t *pubkey, size_t pubkey_len,
                        KyberParamSet param,
                        uint8_t *ciphertext, size_t *ct_len,
                        uint8_t *shared_secret);

/* Decapsulate: recover shared secret from ciphertext + secret key */
KyberError kyber_decaps(const uint8_t *seckey, size_t seckey_len,
                        KyberParamSet param,
                        const uint8_t *ciphertext, size_t ct_len,
                        uint8_t *shared_secret);

/* Free keypair memory (securely wipes secret key) */
void kyber_keypair_free(KyberKeypair *kp);

/* Compute a short, human-comparable fingerprint of a public key (BLAKE2b of
 * the key bytes, rendered as hex groups, e.g. "7F3A 9C12 4E8B D061 5A77").
 * Two parties compare this out-of-band to confirm a key is authentic. */
#define KYBER_FINGERPRINT_LEN 32   /* buffer size for the formatted string */
void kyber_fingerprint(const uint8_t *pubkey, size_t pubkey_len,
                       char *out, size_t out_size);

/* --- Symmetric crypto (AES-256-GCM) --- */

/* Derive symmetric key + nonce from shared secret via BLAKE2b KDF */
KyberError kyber_kdf(const uint8_t *shared_secret,
                     const uint8_t *context, size_t context_len,
                     uint64_t subkey_id,
                     uint8_t *key_out, uint8_t *nonce_out);

/* Check if AES-256-GCM hardware acceleration is available */
bool kyber_aes256gcm_available(void);

/* Encrypt plaintext with AES-256-GCM. out must have room for len + TAG_LEN */
KyberError kyber_sym_encrypt(const uint8_t *key, const uint8_t *nonce,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t len,
                             uint8_t *ciphertext, uint8_t *tag);

/* Decrypt ciphertext with AES-256-GCM. Returns ERR_TAMPERED on auth failure */
KyberError kyber_sym_decrypt(const uint8_t *key, const uint8_t *nonce,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t len,
                             const uint8_t *tag,
                             uint8_t *plaintext);

#endif /* KYBER_CRYPTO_H */
