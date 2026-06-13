#include "archive.h"
#include "compress.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#else
#include <dirent.h>
#include <unistd.h>
#endif

#include <sodium.h>

/* Internal progress callback storage */
static KyberProgressCb g_progress_cb = NULL;
static void           *g_progress_ud = NULL;

void kyber_archive_set_progress(KyberArchive *arc,
                                KyberProgressCb cb, void *userdata)
{
    (void)arc;
    g_progress_cb = cb;
    g_progress_ud = userdata;
}

static void report_progress(uint32_t current, uint32_t total, const char *name)
{
    if (g_progress_cb) {
        g_progress_cb(current, total, name, g_progress_ud);
    }
}

/* ---------- File table serialization ---------- */

/*
 * Serialized file table entry (fixed-size, little-endian):
 *   name:            512 bytes
 *   original_size:   8 bytes
 *   compressed_size: 8 bytes
 *   data_offset:     8 bytes
 *   nonce:           KYBER_SYM_NONCE_LEN bytes
 *   tag:             KYBER_SYM_TAG_LEN bytes
 *   compression:     1 byte
 */
#define ENTRY_SERIAL_SIZE (512 + 8 + 8 + 8 + KYBER_SYM_NONCE_LEN + KYBER_SYM_TAG_LEN + 1)

static void write_le64(uint8_t *dst, uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t read_le64(const uint8_t *src)
{
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--) {
        val = (val << 8) | src[i];
    }
    return val;
}

static void serialize_entry(uint8_t *dst, const KyberFileEntry *e)
{
    size_t off = 0;

    memcpy(dst + off, e->name, 512);                    off += 512;
    write_le64(dst + off, e->original_size);             off += 8;
    write_le64(dst + off, e->compressed_size);           off += 8;
    write_le64(dst + off, e->data_offset);               off += 8;
    memcpy(dst + off, e->nonce, KYBER_SYM_NONCE_LEN);   off += KYBER_SYM_NONCE_LEN;
    memcpy(dst + off, e->tag, KYBER_SYM_TAG_LEN);       off += KYBER_SYM_TAG_LEN;
    dst[off] = e->compression;
}

static void deserialize_entry(const uint8_t *src, KyberFileEntry *e)
{
    size_t off = 0;

    memcpy(e->name, src + off, 512);
    e->name[511] = '\0';                                  off += 512;
    e->original_size   = read_le64(src + off);            off += 8;
    e->compressed_size = read_le64(src + off);            off += 8;
    e->data_offset     = read_le64(src + off);            off += 8;
    memcpy(e->nonce, src + off, KYBER_SYM_NONCE_LEN);    off += KYBER_SYM_NONCE_LEN;
    memcpy(e->tag, src + off, KYBER_SYM_TAG_LEN);        off += KYBER_SYM_TAG_LEN;
    e->compression = src[off];
}

/* ---------- Header read/write ---------- */

static KyberError write_header(FILE *fp, KyberArchive *arc)
{
    uint8_t header[KYBER_HEADER_SIZE];
    memset(header, 0, sizeof(header));

    memcpy(header, KYBER_ARCHIVE_MAGIC, KYBER_ARCHIVE_MAGIC_LEN);
    header[4] = KYBER_ZIP_VERSION_MAJOR;
    header[5] = KYBER_ZIP_VERSION_MINOR;
    header[6] = (uint8_t)arc->param;

    header[7] = (uint8_t)(arc->kem_ct_len & 0xFF);
    header[8] = (uint8_t)((arc->kem_ct_len >> 8) & 0xFF);

    /* table_len at offset 9..12 — may be 0 initially, patched later */
    header[9]  = (uint8_t)(arc->table_enc_len & 0xFF);
    header[10] = (uint8_t)((arc->table_enc_len >> 8) & 0xFF);
    header[11] = (uint8_t)((arc->table_enc_len >> 16) & 0xFF);
    header[12] = (uint8_t)((arc->table_enc_len >> 24) & 0xFF);

    header[13] = (uint8_t)(arc->file_count & 0xFF);
    header[14] = (uint8_t)((arc->file_count >> 8) & 0xFF);
    header[15] = (uint8_t)((arc->file_count >> 16) & 0xFF);
    header[16] = (uint8_t)((arc->file_count >> 24) & 0xFF);

    if (fwrite(header, 1, KYBER_HEADER_SIZE, fp) != KYBER_HEADER_SIZE) {
        return KYBER_ERR_IO;
    }

    return KYBER_OK;
}

static KyberError patch_table_len(FILE *fp, uint32_t table_enc_len)
{
    /* Seek to offset 9 in the header and write table_enc_len */
    if (fseek(fp, 9, SEEK_SET) != 0) return KYBER_ERR_IO;

    uint8_t buf[4];
    buf[0] = (uint8_t)(table_enc_len & 0xFF);
    buf[1] = (uint8_t)((table_enc_len >> 8) & 0xFF);
    buf[2] = (uint8_t)((table_enc_len >> 16) & 0xFF);
    buf[3] = (uint8_t)((table_enc_len >> 24) & 0xFF);

    if (fwrite(buf, 1, 4, fp) != 4) return KYBER_ERR_IO;
    return KYBER_OK;
}

static KyberError read_header(FILE *fp, KyberArchive *arc)
{
    uint8_t header[KYBER_HEADER_SIZE];

    if (fread(header, 1, KYBER_HEADER_SIZE, fp) != KYBER_HEADER_SIZE)
        return KYBER_ERR_IO;

    /* Accept both v1 "KYZ\x01" and v2 "KYZ\x02" magic */
    if (memcmp(header, "KYZ", 3) != 0 || (header[3] != 0x01 && header[3] != 0x02))
        return KYBER_ERR_FORMAT;

    arc->param = (KyberParamSet)header[6];

    arc->kem_ct_len = (size_t)header[7] | ((size_t)header[8] << 8);

    arc->table_enc_len = (uint32_t)header[9] |
                         ((uint32_t)header[10] << 8) |
                         ((uint32_t)header[11] << 16) |
                         ((uint32_t)header[12] << 24);

    arc->file_count = (uint32_t)header[13] |
                      ((uint32_t)header[14] << 8) |
                      ((uint32_t)header[15] << 16) |
                      ((uint32_t)header[16] << 24);

    return KYBER_OK;
}

/* ---------- Path helpers ---------- */

static KyberError ensure_parent_dirs(const char *filepath)
{
    char tmp[1024];
    strncpy(tmp, filepath, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
#ifdef _WIN32
            _mkdir(tmp);
#else
            mkdir(tmp, 0755);
#endif
            *p = '/';
        }
    }
    return KYBER_OK;
}

static bool is_directory(const char *path)
{
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return (stat(path, &st) == 0) && S_ISDIR(st.st_mode);
#endif
}

/* ---------- Archive creation ---------- */

KyberError kyber_archive_create(KyberArchive **arc, KyberParamSet param,
                                const uint8_t *recipient_pubkey,
                                size_t pubkey_len)
{
    *arc = calloc(1, sizeof(KyberArchive));
    if (!*arc) return KYBER_ERR_ALLOC;

    (*arc)->param = param;

    uint8_t shared_secret[KYBER_SHARED_SECRET_LEN];
    KyberError err = kyber_encaps(recipient_pubkey, pubkey_len, param,
                                  (*arc)->kem_ciphertext, &(*arc)->kem_ct_len,
                                  shared_secret);
    if (err != KYBER_OK) {
        free(*arc); *arc = NULL;
        return err;
    }

    uint8_t nonce_discard[KYBER_SYM_NONCE_LEN];
    err = kyber_kdf(shared_secret,
                    (const uint8_t *)"kyz-v1", 6, 0,
                    (*arc)->sym_key, nonce_discard);
    kyber_secure_zero(shared_secret, sizeof(shared_secret));
    kyber_secure_zero(nonce_discard, sizeof(nonce_discard));

    if (err != KYBER_OK) {
        free(*arc); *arc = NULL;
        return err;
    }

    return KYBER_OK;
}

/* ---------- Add file (stores path only) ---------- */

KyberError kyber_archive_add_file(KyberArchive *arc,
                                  const char *filepath,
                                  const char *arcname,
                                  int compression_level)
{
    /* Verify the file exists and get its size */
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return KYBER_ERR_IO;
    fclose(fp);

    uint32_t idx = arc->file_count;
    KyberStagedRef *new_staged = realloc(arc->staged,
                                         (idx + 1) * sizeof(KyberStagedRef));
    if (!new_staged) return KYBER_ERR_ALLOC;

    arc->staged = new_staged;
    arc->file_count = idx + 1;

    KyberStagedRef *ref = &arc->staged[idx];
    memset(ref, 0, sizeof(*ref));
    strncpy(ref->filepath, filepath, sizeof(ref->filepath) - 1);
    strncpy(ref->arcname,
            arcname ? arcname : filepath,
            sizeof(ref->arcname) - 1);
    ref->compression = compression_level;

    /* Normalize backslashes in arcname */
    for (char *p = ref->arcname; *p; p++) {
        if (*p == '\\') *p = '/';
    }

    return KYBER_OK;
}

/* ---------- Add directory (recursive) ---------- */

static void make_arcname(const char *base_dir, const char *full_path,
                         char *out, size_t out_len)
{
    const char *base_name = base_dir;
    for (const char *p = base_dir; *p; p++) {
        if ((*p == '/' || *p == '\\') && *(p + 1) != '\0') {
            base_name = p + 1;
        }
    }

    size_t base_len = strlen(base_dir);
    if (strncmp(full_path, base_dir, base_len) == 0) {
        const char *rel = full_path + base_len;
        while (*rel == '/' || *rel == '\\') rel++;
        if (*rel) {
            snprintf(out, out_len, "%s/%s", base_name, rel);
        } else {
            snprintf(out, out_len, "%s", base_name);
        }
    } else {
        strncpy(out, full_path, out_len - 1);
        out[out_len - 1] = '\0';
    }

    for (char *p = out; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

static KyberError add_dir_recursive(KyberArchive *arc,
                                    const char *dirpath,
                                    const char *base_dir,
                                    int compression_level)
{
#ifdef _WIN32
    char search_path[1024];
    snprintf(search_path, sizeof(search_path), "%s\\*", dirpath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return KYBER_ERR_IO;

    KyberError err = KYBER_OK;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            err = add_dir_recursive(arc, full_path, base_dir, compression_level);
        } else {
            char arcname[512];
            make_arcname(base_dir, full_path, arcname, sizeof(arcname));
            err = kyber_archive_add_file(arc, full_path, arcname,
                                         compression_level);
        }
        if (err != KYBER_OK) break;
    } while (FindNextFileA(hFind, &fd) != 0);

    FindClose(hFind);
    return err;
#else
    DIR *dir = opendir(dirpath);
    if (!dir) return KYBER_ERR_IO;

    KyberError err = KYBER_OK;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, ent->d_name);

        if (is_directory(full_path)) {
            err = add_dir_recursive(arc, full_path, base_dir, compression_level);
        } else {
            char arcname[512];
            make_arcname(base_dir, full_path, arcname, sizeof(arcname));
            err = kyber_archive_add_file(arc, full_path, arcname,
                                         compression_level);
        }
        if (err != KYBER_OK) break;
    }

    closedir(dir);
    return err;
#endif
}

KyberError kyber_archive_add_dir(KyberArchive *arc,
                                 const char *dirpath,
                                 int compression_level)
{
    if (!is_directory(dirpath)) return KYBER_ERR_IO;
    return add_dir_recursive(arc, dirpath, dirpath, compression_level);
}

/* ---------- Process one file: read → compress → encrypt ---------- */

/*
 * Reads a file from disk, compresses it, encrypts the compressed data,
 * writes the encrypted blob to `out_fp`, and fills in the entry metadata.
 * Only one file's data is in memory at a time.
 */
static KyberError process_file(const KyberStagedRef *ref,
                                const uint8_t *sym_key,
                                KyberFileEntry *entry,
                                FILE *out_fp)
{
    /* Read source file */
    FILE *src = fopen(ref->filepath, "rb");
    if (!src) return KYBER_ERR_IO;

    fseek(src, 0, SEEK_END);
    long fsize = ftell(src);
    fseek(src, 0, SEEK_SET);

    if (fsize < 0) { fclose(src); return KYBER_ERR_IO; }

    /* Fill entry metadata */
    memset(entry, 0, sizeof(*entry));
    strncpy(entry->name, ref->arcname, sizeof(entry->name) - 1);
    entry->original_size = (uint64_t)fsize;
    entry->compression = (uint8_t)ref->compression;
    randombytes_buf(entry->nonce, KYBER_SYM_NONCE_LEN);

    /* Handle empty files */
    if (fsize == 0) {
        entry->compressed_size = 0;
        entry->data_offset = (uint64_t)ftell(out_fp);
        fclose(src);
        return KYBER_OK;
    }

    /* Read file data */
    uint8_t *raw = malloc((size_t)fsize);
    if (!raw) { fclose(src); return KYBER_ERR_ALLOC; }

    if (fread(raw, 1, (size_t)fsize, src) != (size_t)fsize) {
        free(raw); fclose(src);
        return KYBER_ERR_IO;
    }
    fclose(src);

    /* Compress */
    uint8_t *compressed = NULL;
    size_t comp_len = 0;
    KyberError err = kyber_compress(raw, (size_t)fsize,
                                    &compressed, &comp_len,
                                    ref->compression);
    free(raw); /* raw data freed immediately */

    if (err != KYBER_OK) return err;

    entry->compressed_size = (uint64_t)comp_len;

    /* Encrypt */
    uint8_t *enc = malloc(comp_len);
    if (!enc) { free(compressed); return KYBER_ERR_ALLOC; }

    err = kyber_sym_encrypt(sym_key, entry->nonce,
                            NULL, 0,
                            compressed, comp_len,
                            enc, entry->tag);
    free(compressed); /* compressed data freed immediately */

    if (err != KYBER_OK) { free(enc); return err; }

    /* Record offset and write encrypted data */
    entry->data_offset = (uint64_t)ftell(out_fp);

    if (fwrite(enc, 1, comp_len, out_fp) != comp_len) {
        free(enc);
        return KYBER_ERR_IO;
    }

    free(enc); /* encrypted data freed immediately */
    return KYBER_OK;
}

/* ---------- Write archive ---------- */

/*
 * Streaming write:
 *   1. Write header (table_len = 0 placeholder) + KEM ciphertext
 *   2. For each file: read → compress → encrypt → write → free
 *   3. Serialize + encrypt the file table, append it
 *   4. Seek back and patch table_len in header
 */
KyberError kyber_archive_write(KyberArchive *arc, const char *outpath)
{
    if (!arc->staged || arc->file_count == 0) return KYBER_ERR_INVALID_PARAM;

    FILE *fp = fopen(outpath, "wb"); /* wb: write-only, no seek-back needed */
    if (!fp) return KYBER_ERR_IO;

    strncpy(arc->path, outpath, sizeof(arc->path) - 1);

    /* Allocate entries array */
    arc->entries = calloc(arc->file_count, sizeof(KyberFileEntry));
    if (!arc->entries) { fclose(fp); return KYBER_ERR_IO; }

    /* Pre-compute table_enc_len so the header is correct from the start */
    arc->table_enc_len = (uint32_t)((size_t)arc->file_count * ENTRY_SERIAL_SIZE);

    /* Step 1: write header + KEM ciphertext */
    KyberError err = write_header(fp, arc);
    if (err != KYBER_OK) { fclose(fp); return err; }

    if (fwrite(arc->kem_ciphertext, 1, arc->kem_ct_len, fp) != arc->kem_ct_len) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    /* Step 2: process each file one at a time */
    for (uint32_t i = 0; i < arc->file_count; i++) {
        report_progress(i + 1, arc->file_count, arc->staged[i].arcname);

        err = process_file(&arc->staged[i], arc->sym_key,
                           &arc->entries[i], fp);
        if (err != KYBER_OK) {
            fclose(fp);
            return err;
        }
    }

    /* Step 3: serialize and encrypt the file table */
    size_t table_plain_len = (size_t)arc->file_count * ENTRY_SERIAL_SIZE;
    uint8_t *table_plain = malloc(table_plain_len);
    if (!table_plain) { fclose(fp); return KYBER_ERR_ALLOC; }

    for (uint32_t i = 0; i < arc->file_count; i++) {
        serialize_entry(table_plain + (size_t)i * ENTRY_SERIAL_SIZE,
                        &arc->entries[i]);
    }

    randombytes_buf(arc->table_nonce, KYBER_SYM_NONCE_LEN);

    uint8_t *table_enc = malloc(table_plain_len);
    if (!table_enc) { free(table_plain); fclose(fp); return KYBER_ERR_ALLOC; }

    err = kyber_sym_encrypt(arc->sym_key, arc->table_nonce,
                            NULL, 0,
                            table_plain, table_plain_len,
                            table_enc, arc->table_tag);
    free(table_plain);
    if (err != KYBER_OK) { free(table_enc); fclose(fp); return err; }

    /* Write table nonce + tag + encrypted table at end */
    if (fwrite(arc->table_nonce, 1, KYBER_SYM_NONCE_LEN, fp) != KYBER_SYM_NONCE_LEN ||
        fwrite(arc->table_tag, 1, KYBER_SYM_TAG_LEN, fp) != KYBER_SYM_TAG_LEN ||
        fwrite(table_enc, 1, arc->table_enc_len, fp) != arc->table_enc_len) {
        free(table_enc); fclose(fp);
        return KYBER_ERR_IO;
    }
    free(table_enc);

    fclose(fp);

    /* Free staged refs — no longer needed */
    free(arc->staged);
    arc->staged = NULL;

    return KYBER_OK;
}

/* ---------- Incremental write ---------- */

KyberError kyber_archive_write_begin(KyberArchive *arc, const char *outpath)
{
    if (!arc->staged || arc->file_count == 0) return KYBER_ERR_INVALID_PARAM;

    FILE *fp = fopen(outpath, "wb");
    if (!fp) return KYBER_ERR_IO;

    strncpy(arc->path, outpath, sizeof(arc->path) - 1);

    arc->entries = calloc(arc->file_count, sizeof(KyberFileEntry));
    if (!arc->entries) { fclose(fp); return KYBER_ERR_IO; }

    arc->table_enc_len = (uint32_t)((size_t)arc->file_count * ENTRY_SERIAL_SIZE);

    KyberError err = write_header(fp, arc);
    if (err != KYBER_OK) { fclose(fp); return err; }

    if (fwrite(arc->kem_ciphertext, 1, arc->kem_ct_len, fp) != arc->kem_ct_len) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    arc->write_fp = fp;
    return KYBER_OK;
}

KyberError kyber_archive_write_next(KyberArchive *arc, uint32_t index)
{
    if (!arc->write_fp || index >= arc->file_count) return KYBER_ERR_INVALID_PARAM;

    report_progress(index + 1, arc->file_count, arc->staged[index].arcname);

    return process_file(&arc->staged[index], arc->sym_key,
                        &arc->entries[index], arc->write_fp);
}

KyberError kyber_archive_write_finish(KyberArchive *arc)
{
    if (!arc->write_fp) return KYBER_ERR_INVALID_PARAM;

    FILE *fp = arc->write_fp;

    size_t table_plain_len = (size_t)arc->file_count * ENTRY_SERIAL_SIZE;
    uint8_t *table_plain = malloc(table_plain_len);
    if (!table_plain) { fclose(fp); arc->write_fp = NULL; return KYBER_ERR_ALLOC; }

    for (uint32_t i = 0; i < arc->file_count; i++) {
        serialize_entry(table_plain + (size_t)i * ENTRY_SERIAL_SIZE,
                        &arc->entries[i]);
    }

    randombytes_buf(arc->table_nonce, KYBER_SYM_NONCE_LEN);

    uint8_t *table_enc = malloc(table_plain_len);
    if (!table_enc) { free(table_plain); fclose(fp); arc->write_fp = NULL; return KYBER_ERR_ALLOC; }

    KyberError err = kyber_sym_encrypt(arc->sym_key, arc->table_nonce,
                                        NULL, 0,
                                        table_plain, table_plain_len,
                                        table_enc, arc->table_tag);
    free(table_plain);
    if (err != KYBER_OK) { free(table_enc); fclose(fp); arc->write_fp = NULL; return err; }

    if (fwrite(arc->table_nonce, 1, KYBER_SYM_NONCE_LEN, fp) != KYBER_SYM_NONCE_LEN ||
        fwrite(arc->table_tag, 1, KYBER_SYM_TAG_LEN, fp) != KYBER_SYM_TAG_LEN ||
        fwrite(table_enc, 1, arc->table_enc_len, fp) != arc->table_enc_len) {
        free(table_enc); fclose(fp); arc->write_fp = NULL;
        return KYBER_ERR_IO;
    }
    free(table_enc);

    fclose(fp);
    arc->write_fp = NULL;

    free(arc->staged);
    arc->staged = NULL;

    return KYBER_OK;
}

/* ---------- Open archive ---------- */

KyberError kyber_archive_open(KyberArchive **arc, const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return KYBER_ERR_IO;

    *arc = calloc(1, sizeof(KyberArchive));
    if (!*arc) { fclose(fp); return KYBER_ERR_ALLOC; }

    strncpy((*arc)->path, path, sizeof((*arc)->path) - 1);

    KyberError err = read_header(fp, *arc);
    if (err != KYBER_OK) {
        fclose(fp); free(*arc); *arc = NULL;
        return err;
    }

    /* Read KEM ciphertext */
    if (fread((*arc)->kem_ciphertext, 1, (*arc)->kem_ct_len, fp)
        != (*arc)->kem_ct_len) {
        fclose(fp); free(*arc); *arc = NULL;
        return KYBER_ERR_IO;
    }

    /*
     * Table is at the END of the file (v2 format).
     * Seek to: file_end - table_enc_len - NONCE_LEN - TAG_LEN
     */
    long table_block_size = (long)(KYBER_SYM_NONCE_LEN + KYBER_SYM_TAG_LEN
                                 + (*arc)->table_enc_len);
    if (fseek(fp, -table_block_size, SEEK_END) != 0) {
        fclose(fp); free(*arc); *arc = NULL;
        return KYBER_ERR_FORMAT;
    }

    /* Read table nonce and tag */
    if (fread((*arc)->table_nonce, 1, KYBER_SYM_NONCE_LEN, fp) != KYBER_SYM_NONCE_LEN ||
        fread((*arc)->table_tag, 1, KYBER_SYM_TAG_LEN, fp) != KYBER_SYM_TAG_LEN) {
        fclose(fp); free(*arc); *arc = NULL;
        return KYBER_ERR_IO;
    }

    fclose(fp);
    return KYBER_OK;
}

/* ---------- Unlock (decrypt file table) ---------- */

KyberError kyber_archive_unlock(KyberArchive *arc,
                                const uint8_t *seckey, size_t seckey_len)
{
    uint8_t shared_secret[KYBER_SHARED_SECRET_LEN];

    KyberError err = kyber_decaps(seckey, seckey_len, arc->param,
                                  arc->kem_ciphertext, arc->kem_ct_len,
                                  shared_secret);
    if (err != KYBER_OK) return err;

    uint8_t nonce_discard[KYBER_SYM_NONCE_LEN];
    err = kyber_kdf(shared_secret,
                    (const uint8_t *)"kyz-v1", 6, 0,
                    arc->sym_key, nonce_discard);
    kyber_secure_zero(shared_secret, sizeof(shared_secret));
    kyber_secure_zero(nonce_discard, sizeof(nonce_discard));
    if (err != KYBER_OK) return err;

    /* Read encrypted table from end of file */
    FILE *fp = fopen(arc->path, "rb");
    if (!fp) return KYBER_ERR_IO;

    long table_block_size = (long)(KYBER_SYM_NONCE_LEN + KYBER_SYM_TAG_LEN
                                 + arc->table_enc_len);
    if (fseek(fp, -table_block_size, SEEK_END) != 0) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    /* Skip nonce + tag (already read in open) */
    if (fseek(fp, KYBER_SYM_NONCE_LEN + KYBER_SYM_TAG_LEN, SEEK_CUR) != 0) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    uint8_t *table_enc = malloc(arc->table_enc_len);
    if (!table_enc) { fclose(fp); return KYBER_ERR_ALLOC; }

    if (fread(table_enc, 1, arc->table_enc_len, fp) != arc->table_enc_len) {
        free(table_enc); fclose(fp);
        return KYBER_ERR_IO;
    }
    fclose(fp);

    /* Decrypt */
    uint8_t *table_plain = malloc(arc->table_enc_len);
    if (!table_plain) { free(table_enc); return KYBER_ERR_ALLOC; }

    err = kyber_sym_decrypt(arc->sym_key, arc->table_nonce,
                            NULL, 0,
                            table_enc, arc->table_enc_len,
                            arc->table_tag,
                            table_plain);
    free(table_enc);
    if (err != KYBER_OK) { free(table_plain); return err; }

    /* Deserialize entries */
    arc->entries = calloc(arc->file_count, sizeof(KyberFileEntry));
    if (!arc->entries) { free(table_plain); return KYBER_ERR_ALLOC; }

    for (uint32_t i = 0; i < arc->file_count; i++) {
        deserialize_entry(table_plain + (size_t)i * ENTRY_SERIAL_SIZE,
                          &arc->entries[i]);
    }

    free(table_plain);
    return KYBER_OK;
}

/* ---------- Extract single file ---------- */

KyberError kyber_archive_extract_file(KyberArchive *arc, uint32_t index,
                                      const char *outdir)
{
    if (index >= arc->file_count) return KYBER_ERR_INVALID_PARAM;
    if (!arc->entries) return KYBER_ERR_WRONG_KEY;

    KyberFileEntry *entry = &arc->entries[index];

    /* Handle empty files */
    if (entry->original_size == 0) {
        char outpath[2048];
        snprintf(outpath, sizeof(outpath), "%s/%s", outdir, entry->name);
        ensure_parent_dirs(outpath);
        FILE *out = fopen(outpath, "wb");
        if (!out) return KYBER_ERR_IO;
        fclose(out);
        report_progress(index + 1, arc->file_count, entry->name);
        return KYBER_OK;
    }

    /* Read encrypted data from archive */
    FILE *fp = fopen(arc->path, "rb");
    if (!fp) return KYBER_ERR_IO;

    if (fseek(fp, (long)entry->data_offset, SEEK_SET) != 0) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    size_t enc_len = (size_t)entry->compressed_size;
    uint8_t *enc_data = malloc(enc_len);
    if (!enc_data) { fclose(fp); return KYBER_ERR_ALLOC; }

    if (fread(enc_data, 1, enc_len, fp) != enc_len) {
        free(enc_data); fclose(fp);
        return KYBER_ERR_IO;
    }
    fclose(fp);

    /* Decrypt */
    uint8_t *compressed = malloc(enc_len);
    if (!compressed) { free(enc_data); return KYBER_ERR_ALLOC; }

    KyberError err = kyber_sym_decrypt(arc->sym_key, entry->nonce,
                                       NULL, 0,
                                       enc_data, enc_len,
                                       entry->tag,
                                       compressed);
    free(enc_data);
    if (err != KYBER_OK) { free(compressed); return err; }

    /* Decompress */
    uint8_t *plaintext = NULL;
    size_t plain_len = (size_t)entry->original_size;

    if (entry->compression == 0) {
        plaintext = compressed;
        compressed = NULL;
    } else {
        err = kyber_decompress(compressed, enc_len,
                               &plaintext, plain_len);
        free(compressed);
        if (err != KYBER_OK) return err;
    }

    /* Write to disk */
    char outpath[2048];
    snprintf(outpath, sizeof(outpath), "%s/%s", outdir, entry->name);
    ensure_parent_dirs(outpath);

    FILE *out = fopen(outpath, "wb");
    if (!out) { free(plaintext); return KYBER_ERR_IO; }

    if (fwrite(plaintext, 1, plain_len, out) != plain_len) {
        fclose(out); free(plaintext);
        return KYBER_ERR_IO;
    }

    fclose(out);
    free(plaintext);

    report_progress(index + 1, arc->file_count, entry->name);
    return KYBER_OK;
}

/* ---------- Extract all ---------- */

KyberError kyber_archive_extract_all(KyberArchive *arc, const char *outdir)
{
    for (uint32_t i = 0; i < arc->file_count; i++) {
        KyberError err = kyber_archive_extract_file(arc, i, outdir);
        if (err != KYBER_OK) return err;
    }
    return KYBER_OK;
}

/* ---------- Cleanup ---------- */

void kyber_archive_free(KyberArchive *arc)
{
    if (!arc) return;
    kyber_secure_zero(arc->sym_key, sizeof(arc->sym_key));

    if (arc->write_fp) {
        fclose(arc->write_fp);
        arc->write_fp = NULL;
    }

    if (arc->staged) {
        free(arc->staged);
    }

    free(arc->entries);
    free(arc);
}
