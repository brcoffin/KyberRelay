#ifndef KYBER_KEYSTORE_H
#define KYBER_KEYSTORE_H

#include "kyber_common.h"
#include "crypto.h"

/* Maximum number of stored keys */
#define KYBER_MAX_KEYS 64

/* Key entry in the keystore */
typedef struct {
    char          label[128];     /* human-readable label */
    KyberParamSet param;          /* parameter set */
    uint8_t      *public_key;
    size_t        public_key_len;
    uint8_t      *secret_key;     /* NULL for public-only imports */
    size_t        secret_key_len;
    bool          has_secret;     /* true if private key is present */
} KeystoreEntry;

/* Maximum tracked verified fingerprints */
#define KYBER_MAX_VERIFIED 256

/* Keystore handle */
typedef struct {
    KeystoreEntry entries[KYBER_MAX_KEYS];
    uint32_t      count;
    char          path[1024];     /* keystore file path */

    /* Fingerprints the user has confirmed out-of-band (loaded from
     * verified.txt). Keyed on fingerprint so a re-imported, different key
     * under the same label is not silently trusted. */
    char          verified[KYBER_MAX_VERIFIED][32];
    uint32_t      verified_count;
} Keystore;

/* Initialize keystore (loads from default path if exists) */
KyberError keystore_init(Keystore *ks);

/* Initialize from a specific path */
KyberError keystore_open(Keystore *ks, const char *path);

/* Generate a new keypair and add to the store */
KyberError keystore_generate(Keystore *ks, const char *label,
                             KyberParamSet param);

/* Import a public key */
KyberError keystore_import_public(Keystore *ks, const char *label,
                                  const char *filepath);

/* Import a keypair (public + secret) */
KyberError keystore_import_keypair(Keystore *ks, const char *label,
                                   const char *filepath);

/* Export a public key to file */
KyberError keystore_export_public(Keystore *ks, uint32_t index,
                                  const char *filepath);

/* Export a keypair to file (prompts/requires confirmation) */
KyberError keystore_export_keypair(Keystore *ks, uint32_t index,
                                   const char *filepath);

/* Remove a key from the store */
KyberError keystore_remove(Keystore *ks, uint32_t index);

/* Find a key by label */
int keystore_find(Keystore *ks, const char *label);

/* Save keystore to disk */
KyberError keystore_save(Keystore *ks);

/* True if the key at index has a fingerprint the user confirmed out-of-band. */
bool keystore_is_verified(const Keystore *ks, uint32_t index);

/* Mark the key at index as verified (persists its fingerprint to verified.txt). */
KyberError keystore_mark_verified(Keystore *ks, uint32_t index);

/* Free keystore resources */
void keystore_free(Keystore *ks);

#endif /* KYBER_KEYSTORE_H */
