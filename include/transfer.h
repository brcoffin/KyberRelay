#ifndef KYBER_TRANSFER_H
#define KYBER_TRANSFER_H

/* Secure-transfer client: moves an already-encrypted .kyz blob to/from a
 * Kyber-Zip relay over HTTP(S). The relay is zero-knowledge — it only ever
 * sees ciphertext — so this layer is concerned solely with transport, not
 * confidentiality. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TRANSFER_OK = 0,
    TRANSFER_ERR_INIT,        /* libcurl failed to initialize            */
    TRANSFER_ERR_OPEN_FILE,   /* could not open the local file           */
    TRANSFER_ERR_NETWORK,     /* connection/transport failure            */
    TRANSFER_ERR_HTTP,        /* server returned a non-2xx status        */
    TRANSFER_ERR_RESPONSE,    /* response was missing/!parseable         */
    TRANSFER_ERR_CANCELED,    /* aborted via the progress callback       */
} TransferStatus;

/* Progress callback. `fraction` is 0.0–1.0 (or -1.0 when the total size is
 * unknown). Return false to abort the transfer. `userdata` is passed through
 * verbatim. */
typedef int (*transfer_progress_cb)(double fraction, void *userdata);

/* Process-wide init/cleanup. Call transfer_global_init() once at startup and
 * transfer_global_cleanup() once at shutdown. */
TransferStatus transfer_global_init(void);
void           transfer_global_cleanup(void);

/* Upload the file at `filepath` to the relay at `base_url`
 * (e.g. "https://relay.example.com" — no trailing slash needed).
 * On success the claim code is written into `code_out` (NUL-terminated);
 * `code_out_size` should be >= 64. */
TransferStatus transfer_upload(const char *base_url, const char *filepath,
                               char *code_out, size_t code_out_size,
                               transfer_progress_cb cb, void *userdata);

/* Download the blob identified by `code` from the relay at `base_url` into
 * `out_path`, overwriting it. */
TransferStatus transfer_download(const char *base_url, const char *code,
                                 const char *out_path,
                                 transfer_progress_cb cb, void *userdata);

/* Human-readable description of a status code. */
const char *transfer_status_str(TransferStatus s);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_TRANSFER_H */
