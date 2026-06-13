#ifndef KYBER_COMPRESS_H
#define KYBER_COMPRESS_H

#include "kyber_common.h"

/* Compression levels */
#define KYBER_COMPRESS_NONE    0
#define KYBER_COMPRESS_FAST    1
#define KYBER_COMPRESS_DEFAULT 6
#define KYBER_COMPRESS_BEST    9

/* Compress data in memory.
 * out_buf is allocated by the function; caller must free().
 * Returns compressed size in out_len. */
KyberError kyber_compress(const uint8_t *in, size_t in_len,
                          uint8_t **out, size_t *out_len,
                          int level);

/* Decompress data in memory.
 * out_buf is allocated by the function; caller must free().
 * orig_len is the expected decompressed size (from archive metadata). */
KyberError kyber_decompress(const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t orig_len);

/* Streaming compression context for large files */
typedef struct KyberCompressStream KyberCompressStream;

KyberError kyber_compress_stream_init(KyberCompressStream **ctx, int level);
KyberError kyber_compress_stream_update(KyberCompressStream *ctx,
                                        const uint8_t *in, size_t in_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_written);
KyberError kyber_compress_stream_finish(KyberCompressStream *ctx,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_written);
void kyber_compress_stream_free(KyberCompressStream *ctx);

#endif /* KYBER_COMPRESS_H */
