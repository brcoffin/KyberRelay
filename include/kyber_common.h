#ifndef KYBER_COMMON_H
#define KYBER_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Kyber-Zip version */
#define KYBER_ZIP_VERSION_MAJOR 0
#define KYBER_ZIP_VERSION_MINOR 1
#define KYBER_ZIP_VERSION_PATCH 0

/* ML-KEM parameter sets */
typedef enum {
    MLKEM_512  = 0,
    MLKEM_768  = 1,
    MLKEM_1024 = 2
} KyberParamSet;

/* Error codes */
typedef enum {
    KYBER_OK                  =  0,
    KYBER_ERR_ALLOC           = -1,
    KYBER_ERR_IO              = -2,
    KYBER_ERR_CRYPTO          = -3,
    KYBER_ERR_COMPRESS        = -4,
    KYBER_ERR_FORMAT          = -5,
    KYBER_ERR_TAMPERED        = -6,
    KYBER_ERR_WRONG_KEY       = -7,
    KYBER_ERR_KEY_NOT_FOUND   = -8,
    KYBER_ERR_INVALID_PARAM   = -9,
} KyberError;

/* Convert error code to human-readable string */
const char *kyber_error_str(KyberError err);

/* Secure memory wipe */
void kyber_secure_zero(void *ptr, size_t len);

#endif /* KYBER_COMMON_H */
