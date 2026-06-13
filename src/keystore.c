#include "keystore.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#endif

/* Default keystore path */
#ifdef _WIN32
#define KEYSTORE_DEFAULT_DIR  "%APPDATA%\\kyber-zip"
#define KEYSTORE_DEFAULT_FILE "keystore.dat"
#else
#define KEYSTORE_DEFAULT_DIR  "~/.kyber-zip"
#define KEYSTORE_DEFAULT_FILE "keystore.dat"
#endif

static KyberError ensure_dir_exists(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == 0) return KYBER_OK;

#ifdef _WIN32
    if (_mkdir(dir) != 0) return KYBER_ERR_IO;
#else
    if (mkdir(dir, 0700) != 0) return KYBER_ERR_IO;
#endif
    return KYBER_OK;
}

static KyberError resolve_default_path(char *out, size_t out_len)
{
    char dir[1024];

#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (!appdata) return KYBER_ERR_IO;
    snprintf(dir, sizeof(dir), "%s\\kyber-zip", appdata);
    snprintf(out, out_len, "%s\\%s", dir, KEYSTORE_DEFAULT_FILE);
#else
    const char *home = getenv("HOME");
    if (!home) return KYBER_ERR_IO;
    snprintf(dir, sizeof(dir), "%s/.kyber-zip", home);
    snprintf(out, out_len, "%s/%s", dir, KEYSTORE_DEFAULT_FILE);
#endif

    return ensure_dir_exists(dir);
}

/* ---------- Verified-fingerprint set ---------- */

static KyberError resolve_verified_path(char *out, size_t out_len)
{
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (!appdata) return KYBER_ERR_IO;
    snprintf(out, out_len, "%s\\kyber-zip\\verified.txt", appdata);
#else
    const char *home = getenv("HOME");
    if (!home) return KYBER_ERR_IO;
    snprintf(out, out_len, "%s/.kyber-zip/verified.txt", home);
#endif
    return KYBER_OK;
}

static void load_verified(Keystore *ks)
{
    ks->verified_count = 0;
    char path[1024];
    if (resolve_verified_path(path, sizeof(path)) != KYBER_OK) return;
    FILE *fp = fopen(path, "rb");
    if (!fp) return;

    char line[64];
    while (fgets(line, sizeof(line), fp) && ks->verified_count < KYBER_MAX_VERIFIED) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' ||
                         line[n-1] == ' '  || line[n-1] == '\t')) {
            line[--n] = '\0';
        }
        if (n == 0) continue;
        strncpy(ks->verified[ks->verified_count], line,
                sizeof(ks->verified[0]) - 1);
        ks->verified[ks->verified_count][sizeof(ks->verified[0]) - 1] = '\0';
        ks->verified_count++;
    }
    fclose(fp);
}

/* ---------- Init ---------- */

KyberError keystore_init(Keystore *ks)
{
    memset(ks, 0, sizeof(*ks));

    /* Resolve into a LOCAL buffer, not ks->path: keystore_open() memsets *ks
     * as its first step, which would zero ks->path mid-call if we passed it as
     * the source — leaving an empty path and a silently-empty keystore. */
    char path[1024];
    KyberError err = resolve_default_path(path, sizeof(path));
    if (err != KYBER_OK) return err;

    /* Try to load existing keystore */
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        err = keystore_open(ks, path);
    } else {
        /* No existing keystore — remember the path so a later save works. */
        strncpy(ks->path, path, sizeof(ks->path) - 1);
        ks->path[sizeof(ks->path) - 1] = '\0';
    }

    /* Load the verified-fingerprint set AFTER keystore_open (which memsets *ks). */
    if (err == KYBER_OK) load_verified(ks);
    return err;
}

KyberError keystore_open(Keystore *ks, const char *path)
{
    memset(ks, 0, sizeof(*ks));
    strncpy(ks->path, path, sizeof(ks->path) - 1);

    FILE *fp = fopen(path, "rb");
    if (!fp) return KYBER_OK; /* empty keystore */

    /* Read header: count */
    uint32_t count;
    if (fread(&count, sizeof(count), 1, fp) != 1) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    if (count > KYBER_MAX_KEYS) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    for (uint32_t i = 0; i < count; i++) {
        KeystoreEntry *e = &ks->entries[i];

        /* Label */
        if (fread(e->label, 1, sizeof(e->label), fp) != sizeof(e->label)) {
            fclose(fp); return KYBER_ERR_IO;
        }

        /* Param set */
        uint8_t param;
        if (fread(&param, 1, 1, fp) != 1) {
            fclose(fp); return KYBER_ERR_IO;
        }
        e->param = (KyberParamSet)param;

        /* Public key */
        if (fread(&e->public_key_len, sizeof(e->public_key_len), 1, fp) != 1) {
            fclose(fp); return KYBER_ERR_IO;
        }
        e->public_key = malloc(e->public_key_len);
        if (!e->public_key) { fclose(fp); return KYBER_ERR_ALLOC; }
        if (fread(e->public_key, 1, e->public_key_len, fp) != e->public_key_len) {
            fclose(fp); return KYBER_ERR_IO;
        }

        /* Has secret? */
        uint8_t has_sec;
        if (fread(&has_sec, 1, 1, fp) != 1) {
            fclose(fp); return KYBER_ERR_IO;
        }
        e->has_secret = (bool)has_sec;

        if (e->has_secret) {
            if (fread(&e->secret_key_len, sizeof(e->secret_key_len), 1, fp) != 1) {
                fclose(fp); return KYBER_ERR_IO;
            }
            e->secret_key = malloc(e->secret_key_len);
            if (!e->secret_key) { fclose(fp); return KYBER_ERR_ALLOC; }
            if (fread(e->secret_key, 1, e->secret_key_len, fp) != e->secret_key_len) {
                fclose(fp); return KYBER_ERR_IO;
            }
        }

        ks->count++;
    }

    fclose(fp);
    return KYBER_OK;
}

/* ---------- Generate ---------- */

KyberError keystore_generate(Keystore *ks, const char *label,
                             KyberParamSet param)
{
    if (ks->count >= KYBER_MAX_KEYS) return KYBER_ERR_ALLOC;

    KyberKeypair kp;
    KyberError err = kyber_keygen(param, &kp);
    if (err != KYBER_OK) return err;

    KeystoreEntry *e = &ks->entries[ks->count];
    memset(e, 0, sizeof(*e));
    strncpy(e->label, label, sizeof(e->label) - 1);
    e->param = param;
    e->public_key = kp.public_key;
    e->public_key_len = kp.public_key_len;
    e->secret_key = kp.secret_key;
    e->secret_key_len = kp.secret_key_len;
    e->has_secret = true;

    ks->count++;
    return KYBER_OK;
}

/* ---------- Key file format ---------- */

/*
 * Kyber-Zip Key File Format (.pub / .kyp)
 *
 * Header (10 bytes):
 *   [0..3]  magic: "KYK\x01"
 *   [4]     type:  0x01 = public only, 0x02 = keypair (public + secret)
 *   [5]     param: 0=ML-KEM-512, 1=ML-KEM-768, 2=ML-KEM-1024
 *   [6..9]  public_key_len (LE32)
 *
 * Body (public-only):
 *   [10..]  public key bytes
 *
 * Body (keypair):
 *   [10..10+publen-1]  public key bytes
 *   [10+publen..10+publen+3]  secret_key_len (LE32)
 *   [10+publen+4..]  secret key bytes
 */

#define KEY_MAGIC     "KYK\x01"
#define KEY_MAGIC_LEN 4
#define KEY_HDR_SIZE  10

#define KEY_TYPE_PUBLIC  0x01
#define KEY_TYPE_KEYPAIR 0x02

static void write_le32(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val & 0xFF);
    dst[1] = (uint8_t)((val >> 8) & 0xFF);
    dst[2] = (uint8_t)((val >> 16) & 0xFF);
    dst[3] = (uint8_t)((val >> 24) & 0xFF);
}

static uint32_t read_le32(const uint8_t *src)
{
    return (uint32_t)src[0] |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/* ---------- Import ---------- */

static KyberError import_key_file(Keystore *ks, const char *label,
                                  const char *filepath, bool expect_secret)
{
    if (ks->count >= KYBER_MAX_KEYS) return KYBER_ERR_ALLOC;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return KYBER_ERR_IO;

    /* Read header */
    uint8_t hdr[KEY_HDR_SIZE];
    if (fread(hdr, 1, KEY_HDR_SIZE, fp) != KEY_HDR_SIZE) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    if (memcmp(hdr, KEY_MAGIC, KEY_MAGIC_LEN) != 0) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    uint8_t type = hdr[4];
    uint8_t param = hdr[5];
    uint32_t publen = read_le32(hdr + 6);

    if (param > 2 || publen == 0 || publen > KYBER_MAX_PUBKEY_LEN) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    if (expect_secret && type != KEY_TYPE_KEYPAIR) {
        fclose(fp);
        return KYBER_ERR_FORMAT;
    }

    KeystoreEntry *e = &ks->entries[ks->count];
    memset(e, 0, sizeof(*e));
    strncpy(e->label, label, sizeof(e->label) - 1);
    e->param = (KyberParamSet)param;

    /* Read public key */
    e->public_key_len = publen;
    e->public_key = malloc(publen);
    if (!e->public_key) { fclose(fp); return KYBER_ERR_ALLOC; }

    if (fread(e->public_key, 1, publen, fp) != publen) {
        free(e->public_key);
        fclose(fp);
        return KYBER_ERR_IO;
    }

    /* Read secret key if present */
    if (type == KEY_TYPE_KEYPAIR) {
        uint8_t seclen_buf[4];
        if (fread(seclen_buf, 1, 4, fp) != 4) {
            free(e->public_key);
            fclose(fp);
            return KYBER_ERR_IO;
        }

        uint32_t seclen = read_le32(seclen_buf);
        if (seclen == 0 || seclen > KYBER_MAX_SECKEY_LEN) {
            free(e->public_key);
            fclose(fp);
            return KYBER_ERR_FORMAT;
        }

        e->secret_key_len = seclen;
        e->secret_key = malloc(seclen);
        if (!e->secret_key) {
            free(e->public_key);
            fclose(fp);
            return KYBER_ERR_ALLOC;
        }

        if (fread(e->secret_key, 1, seclen, fp) != seclen) {
            kyber_secure_zero(e->secret_key, seclen);
            free(e->secret_key);
            free(e->public_key);
            fclose(fp);
            return KYBER_ERR_IO;
        }

        e->has_secret = true;
    } else {
        e->has_secret = false;
    }

    fclose(fp);
    ks->count++;
    return KYBER_OK;
}

KyberError keystore_import_public(Keystore *ks, const char *label,
                                  const char *filepath)
{
    return import_key_file(ks, label, filepath, false);
}

KyberError keystore_import_keypair(Keystore *ks, const char *label,
                                   const char *filepath)
{
    return import_key_file(ks, label, filepath, true);
}

/* ---------- Export ---------- */

KyberError keystore_export_public(Keystore *ks, uint32_t index,
                                  const char *filepath)
{
    if (index >= ks->count) return KYBER_ERR_KEY_NOT_FOUND;

    KeystoreEntry *e = &ks->entries[index];
    FILE *fp = fopen(filepath, "wb");
    if (!fp) return KYBER_ERR_IO;

    /* Write header */
    uint8_t hdr[KEY_HDR_SIZE];
    memcpy(hdr, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr[4] = KEY_TYPE_PUBLIC;
    hdr[5] = (uint8_t)e->param;
    write_le32(hdr + 6, (uint32_t)e->public_key_len);

    if (fwrite(hdr, 1, KEY_HDR_SIZE, fp) != KEY_HDR_SIZE ||
        fwrite(e->public_key, 1, e->public_key_len, fp) != e->public_key_len) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    fclose(fp);
    return KYBER_OK;
}

KyberError keystore_export_keypair(Keystore *ks, uint32_t index,
                                   const char *filepath)
{
    if (index >= ks->count) return KYBER_ERR_KEY_NOT_FOUND;

    KeystoreEntry *e = &ks->entries[index];
    if (!e->has_secret) return KYBER_ERR_KEY_NOT_FOUND;

    FILE *fp = fopen(filepath, "wb");
    if (!fp) return KYBER_ERR_IO;

    /* Write header */
    uint8_t hdr[KEY_HDR_SIZE];
    memcpy(hdr, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr[4] = KEY_TYPE_KEYPAIR;
    hdr[5] = (uint8_t)e->param;
    write_le32(hdr + 6, (uint32_t)e->public_key_len);

    if (fwrite(hdr, 1, KEY_HDR_SIZE, fp) != KEY_HDR_SIZE ||
        fwrite(e->public_key, 1, e->public_key_len, fp) != e->public_key_len) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    /* Write secret key length + data */
    uint8_t seclen_buf[4];
    write_le32(seclen_buf, (uint32_t)e->secret_key_len);

    if (fwrite(seclen_buf, 1, 4, fp) != 4 ||
        fwrite(e->secret_key, 1, e->secret_key_len, fp) != e->secret_key_len) {
        fclose(fp);
        return KYBER_ERR_IO;
    }

    fclose(fp);
    return KYBER_OK;
}

/* ---------- Remove / Find ---------- */

KyberError keystore_remove(Keystore *ks, uint32_t index)
{
    if (index >= ks->count) return KYBER_ERR_KEY_NOT_FOUND;

    KeystoreEntry *e = &ks->entries[index];
    if (e->secret_key) {
        kyber_secure_zero(e->secret_key, e->secret_key_len);
        free(e->secret_key);
    }
    free(e->public_key);

    /* Shift remaining entries */
    for (uint32_t i = index; i < ks->count - 1; i++) {
        ks->entries[i] = ks->entries[i + 1];
    }
    ks->count--;
    memset(&ks->entries[ks->count], 0, sizeof(KeystoreEntry));

    return KYBER_OK;
}

int keystore_find(Keystore *ks, const char *label)
{
    for (uint32_t i = 0; i < ks->count; i++) {
        if (strcmp(ks->entries[i].label, label) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* ---------- Save ---------- */

KyberError keystore_save(Keystore *ks)
{
    FILE *fp = fopen(ks->path, "wb");
    if (!fp) return KYBER_ERR_IO;

    fwrite(&ks->count, sizeof(ks->count), 1, fp);

    for (uint32_t i = 0; i < ks->count; i++) {
        KeystoreEntry *e = &ks->entries[i];

        fwrite(e->label, 1, sizeof(e->label), fp);

        uint8_t param = (uint8_t)e->param;
        fwrite(&param, 1, 1, fp);

        fwrite(&e->public_key_len, sizeof(e->public_key_len), 1, fp);
        fwrite(e->public_key, 1, e->public_key_len, fp);

        uint8_t has_sec = e->has_secret ? 1 : 0;
        fwrite(&has_sec, 1, 1, fp);

        if (e->has_secret) {
            fwrite(&e->secret_key_len, sizeof(e->secret_key_len), 1, fp);
            fwrite(e->secret_key, 1, e->secret_key_len, fp);
        }
    }

    fclose(fp);
    return KYBER_OK;
}

/* ---------- Verification status ---------- */

bool keystore_is_verified(const Keystore *ks, uint32_t index)
{
    if (index >= ks->count) return false;
    const KeystoreEntry *e = &ks->entries[index];
    char fp[KYBER_FINGERPRINT_LEN];
    kyber_fingerprint(e->public_key, e->public_key_len, fp, sizeof(fp));
    for (uint32_t i = 0; i < ks->verified_count; i++) {
        if (strcmp(ks->verified[i], fp) == 0) return true;
    }
    return false;
}

KyberError keystore_mark_verified(Keystore *ks, uint32_t index)
{
    if (index >= ks->count) return KYBER_ERR_KEY_NOT_FOUND;
    const KeystoreEntry *e = &ks->entries[index];
    char fp[KYBER_FINGERPRINT_LEN];
    kyber_fingerprint(e->public_key, e->public_key_len, fp, sizeof(fp));

    /* Already recorded? */
    for (uint32_t i = 0; i < ks->verified_count; i++) {
        if (strcmp(ks->verified[i], fp) == 0) return KYBER_OK;
    }

    if (ks->verified_count < KYBER_MAX_VERIFIED) {
        strncpy(ks->verified[ks->verified_count], fp, sizeof(ks->verified[0]) - 1);
        ks->verified[ks->verified_count][sizeof(ks->verified[0]) - 1] = '\0';
        ks->verified_count++;
    }

    char path[1024];
    if (resolve_verified_path(path, sizeof(path)) != KYBER_OK) return KYBER_ERR_IO;
    FILE *out = fopen(path, "ab");
    if (!out) return KYBER_ERR_IO;
    fprintf(out, "%s\n", fp);
    fclose(out);
    return KYBER_OK;
}

/* ---------- Free ---------- */

void keystore_free(Keystore *ks)
{
    for (uint32_t i = 0; i < ks->count; i++) {
        KeystoreEntry *e = &ks->entries[i];
        if (e->secret_key) {
            kyber_secure_zero(e->secret_key, e->secret_key_len);
            free(e->secret_key);
        }
        free(e->public_key);
    }
    memset(ks, 0, sizeof(*ks));
}
