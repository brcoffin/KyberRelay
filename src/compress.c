#include "compress.h"

#include <stdlib.h>
#include <string.h>
#include "miniz.h"

/* ---------- In-memory compression ---------- */

KyberError kyber_compress(const uint8_t *in, size_t in_len,
                          uint8_t **out, size_t *out_len,
                          int level)
{
    if (level == KYBER_COMPRESS_NONE) {
        *out = malloc(in_len);
        if (!*out) return KYBER_ERR_ALLOC;
        memcpy(*out, in, in_len);
        *out_len = in_len;
        return KYBER_OK;
    }

    mz_ulong bound = mz_compressBound((mz_ulong)in_len);
    *out = malloc(bound);
    if (!*out) return KYBER_ERR_ALLOC;

    mz_ulong dst_len = bound;
    int ret = mz_compress2(*out, &dst_len, in, (mz_ulong)in_len, level);
    if (ret != MZ_OK) {
        free(*out);
        *out = NULL;
        return KYBER_ERR_COMPRESS;
    }

    *out_len = (size_t)dst_len;

    /* Shrink allocation to actual size */
    uint8_t *shrunk = realloc(*out, *out_len);
    if (shrunk) *out = shrunk;

    return KYBER_OK;
}

/* ---------- In-memory decompression ---------- */

KyberError kyber_decompress(const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t orig_len)
{
    *out = malloc(orig_len);
    if (!*out) return KYBER_ERR_ALLOC;

    mz_ulong dst_len = (mz_ulong)orig_len;
    int ret = mz_uncompress(*out, &dst_len, in, (mz_ulong)in_len);
    if (ret != MZ_OK) {
        free(*out);
        *out = NULL;
        return KYBER_ERR_COMPRESS;
    }

    return KYBER_OK;
}

/* ---------- Streaming compression ---------- */

struct KyberCompressStream {
    mz_stream  stream;
    bool       initialized;
};

KyberError kyber_compress_stream_init(KyberCompressStream **ctx, int level)
{
    *ctx = calloc(1, sizeof(KyberCompressStream));
    if (!*ctx) return KYBER_ERR_ALLOC;

    (*ctx)->stream.zalloc = NULL;
    (*ctx)->stream.zfree  = NULL;
    (*ctx)->stream.opaque = NULL;

    int ret = mz_deflateInit(&(*ctx)->stream, level);
    if (ret != MZ_OK) {
        free(*ctx);
        *ctx = NULL;
        return KYBER_ERR_COMPRESS;
    }

    (*ctx)->initialized = true;
    return KYBER_OK;
}

KyberError kyber_compress_stream_update(KyberCompressStream *ctx,
                                        const uint8_t *in, size_t in_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_written)
{
    ctx->stream.next_in  = in;
    ctx->stream.avail_in = (mz_uint32)in_len;
    ctx->stream.next_out = out;
    ctx->stream.avail_out = (mz_uint32)out_cap;

    int ret = mz_deflate(&ctx->stream, MZ_NO_FLUSH);
    if (ret != MZ_OK && ret != MZ_STREAM_END) {
        return KYBER_ERR_COMPRESS;
    }

    *out_written = out_cap - ctx->stream.avail_out;
    return KYBER_OK;
}

KyberError kyber_compress_stream_finish(KyberCompressStream *ctx,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_written)
{
    ctx->stream.next_in  = NULL;
    ctx->stream.avail_in = 0;
    ctx->stream.next_out = out;
    ctx->stream.avail_out = (mz_uint32)out_cap;

    int ret = mz_deflate(&ctx->stream, MZ_FINISH);
    if (ret != MZ_STREAM_END && ret != MZ_OK) {
        return KYBER_ERR_COMPRESS;
    }

    *out_written = out_cap - ctx->stream.avail_out;
    return KYBER_OK;
}

void kyber_compress_stream_free(KyberCompressStream *ctx)
{
    if (!ctx) return;
    if (ctx->initialized) {
        mz_deflateEnd(&ctx->stream);
    }
    free(ctx);
}
