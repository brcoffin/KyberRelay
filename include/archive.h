#ifndef KYBER_ARCHIVE_H
#define KYBER_ARCHIVE_H

#include "kyber_common.h"
#include "crypto.h"
#include <stdio.h>

/*
 * Kyber-Zip Archive Format (.kyz) v2
 *
 * Layout (table-at-end for streaming writes):
 *   [Header]
 *   [KEM Ciphertext]
 *   [File Data block 0]
 *   [File Data block 1]
 *   ...
 *   [Table Nonce]           KYBER_SYM_NONCE_LEN bytes
 *   [Table Tag]             KYBER_SYM_TAG_LEN bytes
 *   [Encrypted File Table]  table_enc_len bytes
 *
 * Header (plaintext, 33 bytes):
 *   magic:      4 bytes  "KYZ\x02"
 *   version:    2 bytes  (major, minor)
 *   param_set:  1 byte   (0=512, 1=768, 2=1024)
 *   ct_len:     2 bytes  KEM ciphertext length (LE16)
 *   table_len:  4 bytes  encrypted file table length (LE32)
 *   file_count: 4 bytes  number of files (LE32)
 *   reserved:   16 bytes
 *
 * The header's table_len is written AFTER all data blocks, by
 * seeking back to offset 9 and patching the value.
 */

#define KYBER_ARCHIVE_MAGIC     "KYZ\x02"
#define KYBER_ARCHIVE_MAGIC_LEN 4
#define KYBER_ARCHIVE_EXT       ".kyz"
#define KYBER_HEADER_SIZE       33  /* 4+2+1+2+4+4+16 */

/* File entry (stored encrypted in the file table) */
typedef struct {
    char     name[512];         /* relative file path (UTF-8) */
    uint64_t original_size;     /* size before compression */
    uint64_t compressed_size;   /* size after compression */
    uint64_t data_offset;       /* offset of encrypted data in archive */
    uint8_t  nonce[KYBER_SYM_NONCE_LEN]; /* unique nonce for this file */
    uint8_t  tag[KYBER_SYM_TAG_LEN];     /* AEAD tag for this file */
    uint8_t  compression;       /* compression level used (0 = none) */
} KyberFileEntry;

/* Staged file reference (path only — data read at write time) */
typedef struct {
    char filepath[1024];    /* source file path on disk */
    char arcname[512];      /* name inside the archive */
    int  compression;       /* compression level */
} KyberStagedRef;

/* Archive handle */
typedef struct {
    KyberParamSet    param;
    uint32_t         file_count;
    KyberFileEntry  *entries;
    KyberStagedRef  *staged;        /* staged file refs for writing */
    uint8_t          kem_ciphertext[KYBER_MAX_CIPHERTEXT];
    size_t           kem_ct_len;
    uint8_t          sym_key[KYBER_SYM_KEY_LEN];   /* derived after decaps */
    uint8_t          table_nonce[KYBER_SYM_NONCE_LEN]; /* nonce for file table encryption */
    uint8_t          table_tag[KYBER_SYM_TAG_LEN];     /* tag for file table */
    uint32_t         table_enc_len; /* encrypted file table length */
    char             path[1024];                     /* archive file path */
    FILE            *write_fp;     /* open file handle during incremental write */
} KyberArchive;

/* --- Archive creation --- */

/* Create a new archive for writing */
KyberError kyber_archive_create(KyberArchive **arc, KyberParamSet param,
                                const uint8_t *recipient_pubkey,
                                size_t pubkey_len);

/* Add a file to the archive */
KyberError kyber_archive_add_file(KyberArchive *arc,
                                  const char *filepath,
                                  const char *arcname,
                                  int compression_level);

/* Add a directory recursively */
KyberError kyber_archive_add_dir(KyberArchive *arc,
                                 const char *dirpath,
                                 int compression_level);

/* Write the archive to disk (blocking — processes all files at once) */
KyberError kyber_archive_write(KyberArchive *arc, const char *outpath);

/* Incremental write: begin opens the file and writes the header */
KyberError kyber_archive_write_begin(KyberArchive *arc, const char *outpath);

/* Incremental write: process a single file by index, returns KYBER_OK on success */
KyberError kyber_archive_write_next(KyberArchive *arc, uint32_t index);

/* Incremental write: finalize (encrypt file table, close file) */
KyberError kyber_archive_write_finish(KyberArchive *arc);

/* --- Archive reading --- */

/* Open an existing archive (reads header, does not decrypt) */
KyberError kyber_archive_open(KyberArchive **arc, const char *path);

/* Decrypt the archive using a secret key (decaps + decrypt file table) */
KyberError kyber_archive_unlock(KyberArchive *arc,
                                const uint8_t *seckey, size_t seckey_len);

/* Extract a single file by index */
KyberError kyber_archive_extract_file(KyberArchive *arc, uint32_t index,
                                      const char *outdir);

/* Extract all files */
KyberError kyber_archive_extract_all(KyberArchive *arc, const char *outdir);

/* --- Cleanup --- */

void kyber_archive_free(KyberArchive *arc);

/* --- Progress callback --- */
typedef void (*KyberProgressCb)(uint32_t current, uint32_t total,
                                const char *filename, void *userdata);

/* Set progress callback for long operations */
void kyber_archive_set_progress(KyberArchive *arc,
                                KyberProgressCb cb, void *userdata);

#endif /* KYBER_ARCHIVE_H */
