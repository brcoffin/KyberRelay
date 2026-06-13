#include "cli.h"
#include "kyber_common.h"
#include "crypto.h"
#include "compress.h"
#include "archive.h"
#include "keystore.h"
#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
/* MSVC doesn't define S_ISDIR */
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#else
#include <dirent.h>
#include <unistd.h>
#endif

void cli_usage(const char *progname)
{
    fprintf(stderr,
        "Kyber-Zip: Post-Quantum Encrypted Archive Tool\n"
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  keygen   Generate a new ML-KEM keypair\n"
        "  pack     Compress and encrypt files into a .kyz archive\n"
        "  unpack   Decrypt and extract a .kyz archive\n"
        "  list     List files in a .kyz archive\n"
        "  keys     List keystore keys + fingerprints (--remove <label> to delete)\n"
        "  verify   Show or check a key's fingerprint: verify <label> [expected]\n"
        "  watch    Auto-encrypt+send files dropped in a folder, log claim codes\n"
        "  recv     Download + decrypt one archive by claim code\n"
        "  recv-watch  Auto-download+decrypt as new claim codes appear\n\n"
        "Options:\n"
        "  --algorithm <512|768|1024>  ML-KEM parameter set (default: 768)\n"
        "  --key <label>              Key label from keystore\n"
        "  --recipient <label>        Recipient's public key label\n"
        "  --output <path>            Output file/directory\n"
        "  --no-compress              Store files without compression\n"
        "  --help                     Show this help\n\n",
        progname);
}

/* ---------- keygen ---------- */

int cli_keygen(int argc, char **argv)
{
    const char *label = NULL;
    KyberParamSet param = MLKEM_768;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            int val = atoi(argv[++i]);
            if (val == 512) param = MLKEM_512;
            else if (val == 768) param = MLKEM_768;
            else if (val == 1024) param = MLKEM_1024;
            else {
                fprintf(stderr, "Error: invalid algorithm '%s'\n", argv[i]);
                return 1;
            }
        } else if (!label) {
            label = argv[i];
        }
    }

    if (!label) {
        fprintf(stderr, "Usage: kyber-cli keygen <label> [--algorithm 512|768|1024]\n");
        return 1;
    }

    Keystore ks;
    KyberError err = keystore_init(&ks);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error initializing keystore: %s\n", kyber_error_str(err));
        return 1;
    }

    printf("Generating ML-KEM-%d keypair '%s'...\n",
           param == MLKEM_512 ? 512 : param == MLKEM_768 ? 768 : 1024, label);

    err = keystore_generate(&ks, label, param);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error: %s\n", kyber_error_str(err));
        keystore_free(&ks);
        return 1;
    }

    err = keystore_save(&ks);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error saving keystore: %s\n", kyber_error_str(err));
        keystore_free(&ks);
        return 1;
    }

    printf("Keypair '%s' generated and saved.\n", label);
    keystore_free(&ks);
    return 0;
}

/* ---------- pack ---------- */

int cli_pack(int argc, char **argv)
{
    const char *recipient = NULL;
    const char *output = NULL;
    KyberParamSet param = MLKEM_768;
    int compress_level = KYBER_COMPRESS_DEFAULT;
    const char **files = NULL;
    int file_count = 0;

    /* Parse arguments */
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--recipient") == 0 && i + 1 < argc) {
            recipient = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            int val = atoi(argv[++i]);
            if (val == 512) param = MLKEM_512;
            else if (val == 1024) param = MLKEM_1024;
            else param = MLKEM_768;
        } else if (strcmp(argv[i], "--no-compress") == 0) {
            compress_level = KYBER_COMPRESS_NONE;
        } else {
            file_count++;
            files = realloc(files, file_count * sizeof(char *));
            files[file_count - 1] = argv[i];
        }
    }

    if (!recipient || file_count == 0) {
        fprintf(stderr, "Usage: kyber-cli pack --recipient <label> [--output file.kyz] <files...>\n");
        free(files);
        return 1;
    }

    if (!output) output = "archive.kyz";

    /* Load keystore and find recipient */
    Keystore ks;
    KyberError err = keystore_init(&ks);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error: %s\n", kyber_error_str(err));
        free(files);
        return 1;
    }

    int idx = keystore_find(&ks, recipient);
    if (idx < 0) {
        fprintf(stderr, "Error: recipient key '%s' not found\n", recipient);
        keystore_free(&ks);
        free(files);
        return 1;
    }

    KeystoreEntry *recip = &ks.entries[idx];

    if (!keystore_is_verified(&ks, (uint32_t)idx)) {
        fprintf(stderr,
            "WARNING: recipient key '%s' is not verified. Verify its fingerprint with\n"
            "         'kyber-cli verify %s <fingerprint>' before trusting it.\n",
            recipient, recipient);
    }

    /* Create archive */
    KyberArchive *arc;
    err = kyber_archive_create(&arc, param, recip->public_key, recip->public_key_len);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error creating archive: %s\n", kyber_error_str(err));
        keystore_free(&ks);
        free(files);
        return 1;
    }

    /* Add files and directories */
    for (int i = 0; i < file_count; i++) {
        printf("Adding: %s\n", files[i]);

        struct stat st;
        if (stat(files[i], &st) != 0) {
            fprintf(stderr, "Error: cannot access '%s'\n", files[i]);
            kyber_archive_free(arc);
            keystore_free(&ks);
            free(files);
            return 1;
        }

        if (S_ISDIR(st.st_mode)) {
            err = kyber_archive_add_dir(arc, files[i], compress_level);
        } else {
            err = kyber_archive_add_file(arc, files[i], NULL, compress_level);
        }

        if (err != KYBER_OK) {
            fprintf(stderr, "Error adding '%s': %s\n", files[i], kyber_error_str(err));
            kyber_archive_free(arc);
            keystore_free(&ks);
            free(files);
            return 1;
        }
    }

    /* Write archive */
    printf("Writing archive: %s\n", output);
    err = kyber_archive_write(arc, output);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error writing archive: %s\n", kyber_error_str(err));
    } else {
        printf("Archive created successfully.\n");
    }

    kyber_archive_free(arc);
    keystore_free(&ks);
    free(files);
    return (err == KYBER_OK) ? 0 : 1;
}

/* ---------- unpack ---------- */

int cli_unpack(int argc, char **argv)
{
    const char *key_label = NULL;
    const char *archive_path = NULL;
    const char *output_dir = ".";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_label = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else {
            archive_path = argv[i];
        }
    }

    if (!archive_path || !key_label) {
        fprintf(stderr, "Usage: kyber-cli unpack --key <label> [--output dir] <archive.kyz>\n");
        return 1;
    }

    /* Load keystore */
    Keystore ks;
    KyberError err = keystore_init(&ks);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error: %s\n", kyber_error_str(err));
        return 1;
    }

    int idx = keystore_find(&ks, key_label);
    if (idx < 0 || !ks.entries[idx].has_secret) {
        fprintf(stderr, "Error: private key '%s' not found\n", key_label);
        keystore_free(&ks);
        return 1;
    }

    /* Open archive */
    KyberArchive *arc;
    err = kyber_archive_open(&arc, archive_path);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error opening archive: %s\n", kyber_error_str(err));
        keystore_free(&ks);
        return 1;
    }

    /* Unlock */
    KeystoreEntry *key = &ks.entries[idx];
    err = kyber_archive_unlock(arc, key->secret_key, key->secret_key_len);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error decrypting archive: %s\n", kyber_error_str(err));
        kyber_archive_free(arc);
        keystore_free(&ks);
        return 1;
    }

    /* Extract */
    printf("Extracting to: %s\n", output_dir);
    err = kyber_archive_extract_all(arc, output_dir);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error extracting: %s\n", kyber_error_str(err));
    } else {
        printf("Extraction complete.\n");
    }

    kyber_archive_free(arc);
    keystore_free(&ks);
    return (err == KYBER_OK) ? 0 : 1;
}

/* ---------- list ---------- */

int cli_list(int argc, char **argv)
{
    const char *key_label = NULL;
    const char *archive_path = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_label = argv[++i];
        } else {
            archive_path = argv[i];
        }
    }

    if (!archive_path || !key_label) {
        fprintf(stderr, "Usage: kyber-cli list --key <label> <archive.kyz>\n");
        return 1;
    }

    /* Open and unlock */
    Keystore ks;
    keystore_init(&ks);

    int idx = keystore_find(&ks, key_label);
    if (idx < 0 || !ks.entries[idx].has_secret) {
        fprintf(stderr, "Error: private key '%s' not found\n", key_label);
        keystore_free(&ks);
        return 1;
    }

    KyberArchive *arc;
    KyberError err = kyber_archive_open(&arc, archive_path);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error: %s\n", kyber_error_str(err));
        keystore_free(&ks);
        return 1;
    }

    KeystoreEntry *key = &ks.entries[idx];
    err = kyber_archive_unlock(arc, key->secret_key, key->secret_key_len);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error decrypting: %s\n", kyber_error_str(err));
        kyber_archive_free(arc);
        keystore_free(&ks);
        return 1;
    }

    /* Print file list */
    printf("Archive: %s (%u files)\n", archive_path, arc->file_count);
    printf("%-40s %12s %12s %s\n", "Name", "Size", "Compressed", "Comp.");
    printf("%-40s %12s %12s %s\n", "----", "----", "----------", "-----");

    for (uint32_t i = 0; i < arc->file_count; i++) {
        KyberFileEntry *e = &arc->entries[i];
        printf("%-40s %12llu %12llu %s\n",
               e->name,
               (unsigned long long)e->original_size,
               (unsigned long long)e->compressed_size,
               e->compression ? "deflate" : "store");
    }

    kyber_archive_free(arc);
    keystore_free(&ks);
    return 0;
}

/* ---------- keys (list keystore) ---------- */

int cli_keys(int argc, char **argv)
{
    const char *remove_label = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--remove") == 0 && i + 1 < argc) {
            remove_label = argv[++i];
        }
    }

    Keystore ks;
    KyberError err = keystore_init(&ks);
    if (err != KYBER_OK) {
        fprintf(stderr, "Error opening keystore: %s\n", kyber_error_str(err));
        return 1;
    }

    if (remove_label) {
        int idx = keystore_find(&ks, remove_label);
        if (idx < 0) {
            fprintf(stderr, "Error: key '%s' not found.\n", remove_label);
            keystore_free(&ks);
            return 1;
        }
        keystore_remove(&ks, (uint32_t)idx);
        if (keystore_save(&ks) != KYBER_OK) {
            fprintf(stderr, "Error: could not save keystore.\n");
            keystore_free(&ks);
            return 1;
        }
        printf("Removed key '%s'.\n", remove_label);
        keystore_free(&ks);
        return 0;
    }

    printf("keystore path : %s\n", ks.path);
    printf("key count     : %u\n", ks.count);
    for (uint32_t i = 0; i < ks.count; i++) {
        KeystoreEntry *e = &ks.entries[i];
        char fp[KYBER_FINGERPRINT_LEN];
        kyber_fingerprint(e->public_key, e->public_key_len, fp, sizeof(fp));
        printf("  [%u] %-20s %-8s %-12s fp: %s\n", i, e->label,
               e->has_secret ? "keypair" : "public",
               keystore_is_verified(&ks, i) ? "[verified]" : "[UNVERIFIED]", fp);
    }
    keystore_free(&ks);
    return 0;
}

/* ---------- verify (compare a key fingerprint) ---------- */

/* Normalize a fingerprint for comparison: drop spaces, uppercase hex. */
static void normalize_fp(const char *in, char *out, size_t out_size)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == ':' || c == '-') continue;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        out[j++] = c;
    }
    out[j] = '\0';
}

int cli_verify(int argc, char **argv)
{
    const char *label = NULL;
    /* Remaining positionals form the expected fingerprint (may be unquoted). */
    char expected[128] = {0};

    for (int i = 0; i < argc; i++) {
        if (!label) {
            label = argv[i];
        } else {
            if (expected[0]) strncat(expected, " ", sizeof(expected) - strlen(expected) - 1);
            strncat(expected, argv[i], sizeof(expected) - strlen(expected) - 1);
        }
    }

    if (!label) {
        fprintf(stderr, "Usage: kyber-cli verify <label> [expected-fingerprint]\n");
        return 1;
    }

    Keystore ks;
    if (keystore_init(&ks) != KYBER_OK) {
        fprintf(stderr, "Error: could not open keystore.\n");
        return 1;
    }
    int idx = keystore_find(&ks, label);
    if (idx < 0) {
        fprintf(stderr, "Error: key '%s' not found.\n", label);
        keystore_free(&ks);
        return 1;
    }

    KeystoreEntry *e = &ks.entries[idx];
    char fp[KYBER_FINGERPRINT_LEN];
    kyber_fingerprint(e->public_key, e->public_key_len, fp, sizeof(fp));

    int rc = 0;
    if (!expected[0]) {
        printf("Fingerprint for '%s':\n  %s\n", label, fp);
    } else {
        char a[128], b[128];
        normalize_fp(fp, a, sizeof(a));
        normalize_fp(expected, b, sizeof(b));
        if (strcmp(a, b) == 0) {
            keystore_mark_verified(&ks, (uint32_t)idx);
            printf("MATCH: '%s' fingerprint is %s\n", label, fp);
            printf("Key '%s' marked as verified.\n", label);
        } else {
            printf("MISMATCH!\n  stored:   %s\n  expected: %s\n", fp, expected);
            fprintf(stderr, "WARNING: key does not match the expected fingerprint.\n");
            rc = 1;
        }
    }
    keystore_free(&ks);
    return rc;
}

/* ---------- watch (automated send) ---------- */

/* Create a directory if it does not already exist. Returns 0 on success. */
static int ensure_dir(const char *path)
{
#ifdef _WIN32
    if (CreateDirectoryA(path, NULL)) return 0;
    return (GetLastError() == ERROR_ALREADY_EXISTS) ? 0 : -1;
#else
    if (mkdir(path, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
#endif
}

/* basename of a path, handling both separators. */
static const char *path_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    const char *b = strrchr(p, '\\');
    if (b && (!s || b > s)) s = b;
    return s ? s + 1 : p;
}

/* Minimal JSON string escaping into dst. */
static void json_escape(char *dst, size_t dn, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dn; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\r')   { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if (c == '\t')   { dst[j++] = '\\'; dst[j++] = 't'; }
        else if (c >= 0x20)   { dst[j++] = (char)c; }
        /* other control chars are dropped */
    }
    dst[j] = '\0';
}

/* List up to maxn regular (non-hidden) files in dir. Returns the count. */
#ifdef _WIN32
static int list_dir_files(const char *dir, char names[][260], int maxn)
{
    char pat[1024];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int c = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.cFileName[0] == '.') continue;
        if (c < maxn) {
            strncpy(names[c], fd.cFileName, 259);
            names[c][259] = '\0';
            c++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return c;
}
#else
static int list_dir_files(const char *dir, char names[][260], int maxn)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int c = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || S_ISDIR(st.st_mode)) continue;
        if (c < maxn) {
            strncpy(names[c], e->d_name, 259);
            names[c][259] = '\0';
            c++;
        }
    }
    closedir(d);
    return c;
}
#endif

/* Move src into sentdir, avoiding clobber by adding a numeric prefix on
 * collision. Writes the final path into out. Returns 0 on success. */
static int move_to_sent(const char *src, const char *sentdir,
                        const char *name, char *out, size_t out_size)
{
    struct stat st;
    snprintf(out, out_size, "%s/%s", sentdir, name);
    if (stat(out, &st) == 0) {
        for (int n = 1; n < 100000; n++) {
            snprintf(out, out_size, "%s/%d_%s", sentdir, n, name);
            if (stat(out, &st) != 0) break;
        }
    }
#ifdef _WIN32
    return MoveFileExA(src, out, MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
    return (rename(src, out) == 0) ? 0 : -1;
#endif
}

/* Append one JSON-Lines record to the send log. */
static void append_log(const char *logpath, const char *name, long size,
                       const char *code, const char *relay)
{
    FILE *fp = fopen(logpath, "ab");
    if (!fp) return;

    char ts[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (tm) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm);
    else    snprintf(ts, sizeof(ts), "unknown");

    char ename[1024], erelay[640];
    json_escape(ename, sizeof(ename), name);
    json_escape(erelay, sizeof(erelay), relay);

    fprintf(fp,
        "{\"time\":\"%s\",\"file\":\"%s\",\"size\":%ld,\"code\":\"%s\",\"relay\":\"%s\"}\n",
        ts, ename, size, code, erelay);
    fclose(fp);
}

/* Load the saved relay URL (same file the GUI writes). */
static int load_saved_relay(char *out, size_t out_size)
{
    char path[1024];
#ifdef _WIN32
    const char *base = getenv("APPDATA");
    if (!base) return -1;
    snprintf(path, sizeof(path), "%s\\kyber-zip\\relay.txt", base);
#else
    const char *base = getenv("HOME");
    if (!base) return -1;
    snprintf(path, sizeof(path), "%s/.kyber-zip/relay.txt", base);
#endif
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(out, 1, out_size - 1, fp);
    fclose(fp);
    out[n] = '\0';
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r' ||
                     out[n-1] == ' '  || out[n-1] == '\t')) {
        out[--n] = '\0';
    }
    return out[0] ? 0 : -1;
}

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

/* Encrypt one source file to a temp .kyz, upload it, and return the code. */
static int send_one_file(const char *srcpath, const char *name,
                         const char *workdir, KyberParamSet param,
                         KeystoreEntry *recip, int compress_level,
                         const char *relay, char *code_out, size_t code_size)
{
    char kyz[1024];
    snprintf(kyz, sizeof(kyz), "%s/%s.kyz", workdir, name);

    KyberArchive *arc = NULL;
    KyberError err = kyber_archive_create(&arc, param,
                                          recip->public_key, recip->public_key_len);
    if (err != KYBER_OK) {
        fprintf(stderr, "  create failed: %s\n", kyber_error_str(err));
        return -1;
    }
    err = kyber_archive_add_file(arc, srcpath, name, compress_level);
    if (err != KYBER_OK) {
        fprintf(stderr, "  add failed: %s\n", kyber_error_str(err));
        kyber_archive_free(arc);
        return -1;
    }
    err = kyber_archive_write(arc, kyz);
    kyber_archive_free(arc);
    if (err != KYBER_OK) {
        fprintf(stderr, "  write failed: %s\n", kyber_error_str(err));
        return -1;
    }

    TransferStatus ts = transfer_upload(relay, kyz, code_out, code_size, NULL, NULL);
    remove(kyz);
    if (ts != TRANSFER_OK) {
        fprintf(stderr, "  upload failed: %s\n", transfer_status_str(ts));
        return -1;
    }
    return 0;
}

int cli_watch(int argc, char **argv)
{
    const char *recipient = NULL;
    const char *relay_arg = NULL;
    const char *outbox = "outbox";
    const char *sentdir = "sent";
    const char *logpath = "sent-log.jsonl";
    KyberParamSet param = MLKEM_768;
    int compress_level = KYBER_COMPRESS_DEFAULT;
    int interval_ms = 2000;
    int settle_secs = 2;
    int require_verified = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--require-verified") == 0)               require_verified = 1;
        else if (strcmp(argv[i], "--recipient") == 0 && i + 1 < argc) recipient = argv[++i];
        else if (strcmp(argv[i], "--relay") == 0 && i + 1 < argc)     relay_arg = argv[++i];
        else if (strcmp(argv[i], "--outbox") == 0 && i + 1 < argc)    outbox = argv[++i];
        else if (strcmp(argv[i], "--sent") == 0 && i + 1 < argc)      sentdir = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc)       logpath = argv[++i];
        else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc)  interval_ms = atoi(argv[++i]) * 1000;
        else if (strcmp(argv[i], "--settle") == 0 && i + 1 < argc)    settle_secs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--no-compress") == 0)               compress_level = KYBER_COMPRESS_NONE;
        else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            int val = atoi(argv[++i]);
            if (val == 512) param = MLKEM_512;
            else if (val == 1024) param = MLKEM_1024;
            else param = MLKEM_768;
        } else {
            outbox = argv[i]; /* positional = outbox dir */
        }
    }

    if (interval_ms < 200) interval_ms = 200;

    if (!recipient) {
        fprintf(stderr,
            "Usage: kyber-cli watch --recipient <label> [--relay <url>]\n"
            "                       [--outbox dir] [--sent dir] [--log file]\n"
            "                       [--interval secs] [--settle secs]\n"
            "                       [--algorithm 512|768|1024] [--no-compress]\n");
        return 1;
    }

    /* Resolve relay: --relay, else the saved relay.txt. */
    char relay_buf[640];
    const char *relay = relay_arg;
    if (!relay) {
        if (load_saved_relay(relay_buf, sizeof(relay_buf)) == 0) {
            relay = relay_buf;
        } else {
            fprintf(stderr, "Error: no relay URL. Pass --relay <url> or set one in the GUI first.\n");
            return 1;
        }
    }

    /* Load recipient public key. */
    Keystore ks;
    if (keystore_init(&ks) != KYBER_OK) {
        fprintf(stderr, "Error: could not open keystore.\n");
        return 1;
    }
    int idx = keystore_find(&ks, recipient);
    if (idx < 0) {
        fprintf(stderr, "Error: recipient key '%s' not found.\n", recipient);
        keystore_free(&ks);
        return 1;
    }
    KeystoreEntry *recip = &ks.entries[idx];

    /* Warn (or refuse) if the recipient's key hasn't been verified out-of-band. */
    if (!keystore_is_verified(&ks, (uint32_t)idx)) {
        if (require_verified) {
            fprintf(stderr,
                "Error: recipient '%s' is not verified. Confirm its fingerprint with\n"
                "       'kyber-cli verify %s <fingerprint>' or drop --require-verified.\n",
                recipient, recipient);
            keystore_free(&ks);
            return 1;
        }
        fprintf(stderr,
            "WARNING: recipient key '%s' is NOT verified — you may be encrypting to an\n"
            "         impostor. Verify its fingerprint: 'kyber-cli verify %s <fingerprint>'\n\n",
            recipient, recipient);
    }

    /* Prepare directories. */
    char workdir[1024];
    snprintf(workdir, sizeof(workdir), "%s/.tmp", sentdir);
    if (ensure_dir(outbox) != 0 || ensure_dir(sentdir) != 0 || ensure_dir(workdir) != 0) {
        fprintf(stderr, "Error: could not create outbox/sent directories.\n");
        keystore_free(&ks);
        return 1;
    }

    if (transfer_global_init() != TRANSFER_OK) {
        fprintf(stderr, "Error: could not initialize network layer.\n");
        keystore_free(&ks);
        return 1;
    }

    printf("Kyber-Zip watcher started.\n");
    printf("  recipient : %s\n", recipient);
    printf("  relay     : %s\n", relay);
    printf("  outbox    : %s\n", outbox);
    printf("  sent      : %s\n", sentdir);
    printf("  log       : %s\n", logpath);
    printf("Watching for files (Ctrl+C to stop)...\n\n");
    fflush(stdout);

    for (;;) {
        char names[1024][260];
        int n = list_dir_files(outbox, names, 1024);

        for (int i = 0; i < n; i++) {
            char src[1024];
            snprintf(src, sizeof(src), "%s/%s", outbox, names[i]);

            struct stat st;
            if (stat(src, &st) != 0) continue;

            /* Skip files still being written (recently modified). */
            if (difftime(time(NULL), st.st_mtime) < settle_secs) continue;

            printf("[+] %s (%ld bytes) ... ", names[i], (long)st.st_size);
            fflush(stdout);

            char code[64] = {0};
            if (send_one_file(src, names[i], workdir, param, recip,
                              compress_level, relay, code, sizeof(code)) != 0) {
                printf("FAILED (left in outbox, will retry)\n");
                continue;
            }

            char finalpath[1024];
            if (move_to_sent(src, sentdir, names[i], finalpath, sizeof(finalpath)) != 0) {
                fprintf(stderr, "  warning: uploaded but could not move to sent: %s\n", src);
            }

            append_log(logpath, names[i], (long)st.st_size, code, relay);
            printf("sent, code %s\n", code);
            fflush(stdout);
        }

        sleep_ms(interval_ms);
    }

    /* not reached (Ctrl+C exits) */
}

/* ---------- receive (download + decrypt) ---------- */

/* Download the blob for `code`, decrypt with `key`, extract into `inbox`.
 * Returns 0 on success, -1 on a transient (retryable) network error, and
 * -2 on a permanent failure (code gone/invalid, or decrypt failed). */
static int recv_to_inbox(const char *relay, const char *code,
                         KeystoreEntry *key, const char *inbox)
{
    char tmp[1100];
    snprintf(tmp, sizeof(tmp), "%s/.recv-%s.kyz", inbox, code);

    TransferStatus ts = transfer_download(relay, code, tmp, NULL, NULL);
    if (ts != TRANSFER_OK) {
        return (ts == TRANSFER_ERR_HTTP) ? -2 : -1;
    }

    KyberArchive *arc = NULL;
    if (kyber_archive_open(&arc, tmp) != KYBER_OK) { remove(tmp); return -2; }
    if (kyber_archive_unlock(arc, key->secret_key, key->secret_key_len) != KYBER_OK) {
        kyber_archive_free(arc); remove(tmp); return -2;
    }
    KyberError e = kyber_archive_extract_all(arc, inbox);
    kyber_archive_free(arc);
    remove(tmp);
    return (e == KYBER_OK) ? 0 : -2;
}

/* Pull a claim code out of a line that is either a bare code or a JSON object
 * with a "code" field (so this can read a plain codes.txt OR a sent-log.jsonl
 * directly). Returns 1 if a code was extracted. */
static int extract_code_from_line(const char *line, char *out, size_t outsz)
{
    const char *k = strstr(line, "\"code\"");
    if (k) {
        const char *colon = strchr(k, ':');
        if (!colon) return 0;
        const char *q1 = strchr(colon, '"');
        if (!q1) return 0;
        q1++;
        const char *q2 = strchr(q1, '"');
        if (!q2) return 0;
        size_t n = (size_t)(q2 - q1);
        if (n == 0 || n >= outsz) return 0;
        memcpy(out, q1, n);
        out[n] = '\0';
        return 1;
    }

    /* Bare token: skip leading space, copy up to whitespace. */
    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') line++;
    if (line[0] == '#' || line[0] == '\0') return 0; /* comment/blank */
    size_t n = 0;
    while (line[n] && line[n] != ' ' && line[n] != '\t' &&
           line[n] != '\r' && line[n] != '\n') n++;
    if (n == 0 || n >= outsz) return 0;
    memcpy(out, line, n);
    out[n] = '\0';
    return 1;
}

/* A small growable set of codes already handled (avoids re-downloading). */
typedef struct { char (*items)[40]; int count; int cap; } CodeSet;

static int codeset_has(CodeSet *s, const char *c)
{
    for (int i = 0; i < s->count; i++)
        if (strcmp(s->items[i], c) == 0) return 1;
    return 0;
}

static void codeset_add(CodeSet *s, const char *c)
{
    if (codeset_has(s, c)) return;
    if (s->count >= s->cap) {
        s->cap = s->cap ? s->cap * 2 : 64;
        s->items = realloc(s->items, (size_t)s->cap * 40);
    }
    strncpy(s->items[s->count], c, 39);
    s->items[s->count][39] = '\0';
    s->count++;
}

static void append_recv_log(const char *logpath, const char *code,
                            const char *status, const char *relay)
{
    FILE *fp = fopen(logpath, "ab");
    if (!fp) return;
    char ts[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (tm) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm);
    else    snprintf(ts, sizeof(ts), "unknown");
    char erelay[640];
    json_escape(erelay, sizeof(erelay), relay);
    fprintf(fp, "{\"time\":\"%s\",\"code\":\"%s\",\"status\":\"%s\",\"relay\":\"%s\"}\n",
            ts, code, status, erelay);
    fclose(fp);
}

/* Resolve relay from --relay or the saved relay.txt. Returns NULL on failure. */
static const char *resolve_relay(const char *relay_arg, char *buf, size_t bufsz)
{
    if (relay_arg) return relay_arg;
    if (load_saved_relay(buf, bufsz) == 0) return buf;
    return NULL;
}

/* Load the recipient's private key from the keystore. */
static KeystoreEntry *load_private_key(Keystore *ks, const char *label)
{
    if (keystore_init(ks) != KYBER_OK) {
        fprintf(stderr, "Error: could not open keystore.\n");
        return NULL;
    }
    int idx = keystore_find(ks, label);
    if (idx < 0 || !ks->entries[idx].has_secret) {
        fprintf(stderr, "Error: private key '%s' not found.\n", label);
        keystore_free(ks);
        return NULL;
    }
    return &ks->entries[idx];
}

int cli_recv(int argc, char **argv)
{
    const char *code = NULL, *key_label = NULL, *relay_arg = NULL;
    const char *output = ".";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)        key_label = argv[++i];
        else if (strcmp(argv[i], "--relay") == 0 && i + 1 < argc) relay_arg = argv[++i];
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) output = argv[++i];
        else code = argv[i];
    }

    if (!code || !key_label) {
        fprintf(stderr, "Usage: kyber-cli recv <code> --key <label> [--relay <url>] [--output dir]\n");
        return 1;
    }

    char relay_buf[640];
    const char *relay = resolve_relay(relay_arg, relay_buf, sizeof(relay_buf));
    if (!relay) {
        fprintf(stderr, "Error: no relay URL. Pass --relay <url> or set one in the GUI first.\n");
        return 1;
    }

    Keystore ks;
    KeystoreEntry *key = load_private_key(&ks, key_label);
    if (!key) return 1;

    if (transfer_global_init() != TRANSFER_OK) {
        fprintf(stderr, "Error: could not initialize network layer.\n");
        keystore_free(&ks);
        return 1;
    }
    ensure_dir(output);

    printf("Downloading %s ...\n", code);
    int r = recv_to_inbox(relay, code, key, output);
    if (r == 0) printf("Received and extracted to: %s\n", output);
    else if (r == -2) fprintf(stderr, "Failed: code is invalid, already used, or expired.\n");
    else fprintf(stderr, "Failed: network error.\n");

    keystore_free(&ks);
    return (r == 0) ? 0 : 1;
}

int cli_recv_watch(int argc, char **argv)
{
    const char *key_label = NULL, *relay_arg = NULL;
    const char *codesfile = "codes.txt", *inbox = "inbox";
    const char *logpath = "received-log.jsonl";
    int interval_ms = 2000;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)         key_label = argv[++i];
        else if (strcmp(argv[i], "--relay") == 0 && i + 1 < argc)  relay_arg = argv[++i];
        else if (strcmp(argv[i], "--codes") == 0 && i + 1 < argc)  codesfile = argv[++i];
        else if (strcmp(argv[i], "--inbox") == 0 && i + 1 < argc)  inbox = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc)    logpath = argv[++i];
        else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) interval_ms = atoi(argv[++i]) * 1000;
    }
    if (interval_ms < 200) interval_ms = 200;

    if (!key_label) {
        fprintf(stderr,
            "Usage: kyber-cli recv-watch --key <label> [--relay <url>]\n"
            "                            [--codes file] [--inbox dir] [--log file]\n"
            "                            [--interval secs]\n");
        return 1;
    }

    char relay_buf[640];
    const char *relay = resolve_relay(relay_arg, relay_buf, sizeof(relay_buf));
    if (!relay) {
        fprintf(stderr, "Error: no relay URL. Pass --relay <url> or set one in the GUI first.\n");
        return 1;
    }

    Keystore ks;
    KeystoreEntry *key = load_private_key(&ks, key_label);
    if (!key) return 1;

    if (transfer_global_init() != TRANSFER_OK) {
        fprintf(stderr, "Error: could not initialize network layer.\n");
        keystore_free(&ks);
        return 1;
    }
    ensure_dir(inbox);

    /* Seed the processed set from any prior received-log so a restart doesn't
     * re-pull (and fail on) codes already consumed. */
    CodeSet processed = {0};
    FILE *lf = fopen(logpath, "rb");
    if (lf) {
        char line[2048];
        while (fgets(line, sizeof(line), lf)) {
            char c[64];
            if (extract_code_from_line(line, c, sizeof(c))) codeset_add(&processed, c);
        }
        fclose(lf);
    }

    printf("Kyber-Zip receiver started.\n");
    printf("  key      : %s\n", key_label);
    printf("  relay    : %s\n", relay);
    printf("  codes    : %s\n", codesfile);
    printf("  inbox    : %s\n", inbox);
    printf("  log      : %s\n", logpath);
    printf("Watching for new claim codes (Ctrl+C to stop)...\n\n");
    fflush(stdout);

    for (;;) {
        FILE *fp = fopen(codesfile, "rb");
        if (fp) {
            char line[2048];
            while (fgets(line, sizeof(line), fp)) {
                char code[64];
                if (!extract_code_from_line(line, code, sizeof(code))) continue;
                if (codeset_has(&processed, code)) continue;

                printf("[v] %s ... ", code);
                fflush(stdout);

                int r = recv_to_inbox(relay, code, key, inbox);
                if (r == 0) {
                    printf("received\n");
                    append_recv_log(logpath, code, "received", relay);
                    codeset_add(&processed, code);
                } else if (r == -2) {
                    printf("failed (gone/invalid)\n");
                    append_recv_log(logpath, code, "failed", relay);
                    codeset_add(&processed, code); /* don't retry a permanent failure */
                } else {
                    printf("network error, will retry\n");
                    /* leave unprocessed so the next pass retries */
                }
                fflush(stdout);
            }
            fclose(fp);
        }
        sleep_ms(interval_ms);
    }

    /* not reached */
}

/* ---------- Main dispatch ---------- */

int cli_run(int argc, char **argv)
{
    if (argc < 2) {
        cli_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0) {
        return cli_keygen(argc - 2, argv + 2);
    } else if (strcmp(cmd, "pack") == 0) {
        return cli_pack(argc - 2, argv + 2);
    } else if (strcmp(cmd, "unpack") == 0) {
        return cli_unpack(argc - 2, argv + 2);
    } else if (strcmp(cmd, "list") == 0) {
        return cli_list(argc - 2, argv + 2);
    } else if (strcmp(cmd, "watch") == 0) {
        return cli_watch(argc - 2, argv + 2);
    } else if (strcmp(cmd, "keys") == 0) {
        return cli_keys(argc - 2, argv + 2);
    } else if (strcmp(cmd, "recv") == 0) {
        return cli_recv(argc - 2, argv + 2);
    } else if (strcmp(cmd, "recv-watch") == 0) {
        return cli_recv_watch(argc - 2, argv + 2);
    } else if (strcmp(cmd, "verify") == 0) {
        return cli_verify(argc - 2, argv + 2);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        cli_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        cli_usage(argv[0]);
        return 1;
    }
}
