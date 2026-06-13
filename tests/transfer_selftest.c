/* Self-test for the transfer client against a running Kyber-Zip relay.
 *
 * Usage: transfer_selftest <base_url>
 * e.g.   transfer_selftest http://localhost:8099
 *
 * Verifies: upload returns a code, download round-trips byte-identically,
 * and a second download of the same code fails (one-time semantics). */

#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_BYTES 50000

static int make_payload(const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    unsigned int seed = 12345u;
    for (int i = 0; i < PAYLOAD_BYTES; i++) {
        seed = seed * 1103515245u + 12345u;        /* deterministic LCG */
        unsigned char b = (unsigned char)(seed >> 16);
        fputc(b, fp);
    }
    fclose(fp);
    return 1;
}

static int files_identical(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return 0; }
    int ca, cb, same = 1;
    do {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) { same = 0; break; }
    } while (ca != EOF);
    fclose(fa);
    fclose(fb);
    return same;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <base_url>\n", argv[0]);
        return 2;
    }
    const char *url = argv[1];

    const char *src = "selftest_src.bin";
    const char *dst = "selftest_dst.bin";

    if (!make_payload(src)) { fprintf(stderr, "could not write payload\n"); return 2; }

    if (transfer_global_init() != TRANSFER_OK) {
        fprintf(stderr, "transfer_global_init failed\n");
        return 2;
    }

    int failures = 0;

    /* 1. Upload */
    char code[64] = {0};
    TransferStatus s = transfer_upload(url, src, code, sizeof(code), NULL, NULL);
    printf("upload: %s  code=%s\n", transfer_status_str(s), code);
    if (s != TRANSFER_OK || code[0] == '\0') { failures++; goto done; }

    /* 2. Download round-trip */
    s = transfer_download(url, code, dst, NULL, NULL);
    printf("download: %s\n", transfer_status_str(s));
    if (s != TRANSFER_OK) { failures++; goto done; }

    if (files_identical(src, dst)) {
        printf("roundtrip: IDENTICAL (%d bytes)\n", PAYLOAD_BYTES);
    } else {
        printf("roundtrip: MISMATCH\n");
        failures++;
    }

    /* 3. Second download must fail (one-time download) */
    s = transfer_download(url, code, dst, NULL, NULL);
    if (s == TRANSFER_ERR_HTTP) {
        printf("reuse: correctly rejected (%s)\n", transfer_status_str(s));
    } else {
        printf("reuse: UNEXPECTED status %s\n", transfer_status_str(s));
        failures++;
    }

done:
    transfer_global_cleanup();
    remove(src);
    remove(dst);

    printf("\n%s\n", failures == 0 ? "ALL CHECKS PASSED" : "FAILURES DETECTED");
    return failures == 0 ? 0 : 1;
}
