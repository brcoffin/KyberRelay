#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

/* ---------- response capture ---------- */

/* The upload response is a tiny JSON object ({"code":"...","expires_in":N}),
 * so a fixed buffer is plenty — anything larger is malformed and rejected. */
typedef struct {
    char   data[512];
    size_t len;
} ResponseBuf;

static size_t write_to_response(void *ptr, size_t size, size_t nmemb, void *ud)
{
    ResponseBuf *rb = (ResponseBuf *)ud;
    size_t n = size * nmemb;
    if (rb->len + n >= sizeof(rb->data)) {
        n = sizeof(rb->data) - rb->len - 1;
    }
    memcpy(rb->data + rb->len, ptr, n);
    rb->len += n;
    rb->data[rb->len] = '\0';
    return size * nmemb; /* report all consumed so curl doesn't error */
}

static size_t write_to_file(void *ptr, size_t size, size_t nmemb, void *ud)
{
    FILE *fp = (FILE *)ud;
    return fwrite(ptr, size, nmemb, fp);
}

static size_t read_from_file(char *buffer, size_t size, size_t nitems, void *ud)
{
    FILE *fp = (FILE *)ud;
    return fread(buffer, size, nitems, fp);
}

/* ---------- progress bridge ---------- */

typedef struct {
    transfer_progress_cb cb;
    void                *userdata;
} ProgressCtx;

static int xferinfo(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
    ProgressCtx *pc = (ProgressCtx *)clientp;
    if (!pc || !pc->cb) return 0;

    /* Use whichever direction is active this transfer. */
    curl_off_t total = ultotal > 0 ? ultotal : dltotal;
    curl_off_t now   = ultotal > 0 ? ulnow   : dlnow;

    double frac = (total > 0) ? (double)now / (double)total : -1.0;
    /* Returning non-zero from a curl progress callback aborts the transfer. */
    return pc->cb(frac, pc->userdata) ? 0 : 1;
}

/* ---------- helpers ---------- */

/* Build "<base>/v1/blob" (and optionally "/<code>") into `out`, trimming a
 * single trailing slash from base. */
static void build_url(char *out, size_t out_size, const char *base,
                      const char *code)
{
    size_t blen = strlen(base);
    while (blen > 0 && base[blen - 1] == '/') blen--;

    if (code) {
        snprintf(out, out_size, "%.*s/v1/blob/%s", (int)blen, base, code);
    } else {
        snprintf(out, out_size, "%.*s/v1/blob", (int)blen, base);
    }
}

/* Extract the value of the "code" field from a minimal JSON object without
 * pulling in a JSON dependency. Returns true on success. */
static int parse_code(const char *json, char *out, size_t out_size)
{
    const char *key = strstr(json, "\"code\"");
    if (!key) return 0;
    const char *colon = strchr(key, ':');
    if (!colon) return 0;
    const char *q1 = strchr(colon, '"');
    if (!q1) return 0;
    q1++;
    const char *q2 = strchr(q1, '"');
    if (!q2) return 0;

    size_t n = (size_t)(q2 - q1);
    if (n == 0 || n >= out_size) return 0;
    memcpy(out, q1, n);
    out[n] = '\0';
    return 1;
}

static TransferStatus map_curl_error(CURLcode rc)
{
    switch (rc) {
        case CURLE_OK:               return TRANSFER_OK;
        case CURLE_ABORTED_BY_CALLBACK: return TRANSFER_ERR_CANCELED;
        default:                     return TRANSFER_ERR_NETWORK;
    }
}

/* ---------- public API ---------- */

TransferStatus transfer_global_init(void)
{
    return (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK)
        ? TRANSFER_OK : TRANSFER_ERR_INIT;
}

void transfer_global_cleanup(void)
{
    curl_global_cleanup();
}

TransferStatus transfer_upload(const char *base_url, const char *filepath,
                               char *code_out, size_t code_out_size,
                               transfer_progress_cb cb, void *userdata)
{
    if (code_out && code_out_size) code_out[0] = '\0';

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return TRANSFER_ERR_OPEN_FILE;

    /* Determine the file size so curl can send a Content-Length. */
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return TRANSFER_ERR_OPEN_FILE; }
    long fsize = ftell(fp);
    if (fsize < 0) { fclose(fp); return TRANSFER_ERR_OPEN_FILE; }
    rewind(fp);

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(fp); return TRANSFER_ERR_INIT; }

    char url[1024];
    build_url(url, sizeof(url), base_url, NULL);

    ResponseBuf resp = { .len = 0 };
    resp.data[0] = '\0';
    ProgressCtx pc = { cb, userdata };

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    /* Avoid a 100-continue round trip on large uploads. */
    headers = curl_slist_append(headers, "Expect:");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_from_file);
    curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)fsize);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &pc);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "kyber-zip/1.0");

    CURLcode rc = curl_easy_perform(curl);

    TransferStatus status = TRANSFER_OK;
    if (rc != CURLE_OK) {
        status = map_curl_error(rc);
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code < 200 || http_code >= 300) {
            status = TRANSFER_ERR_HTTP;
        } else if (!parse_code(resp.data, code_out, code_out_size)) {
            status = TRANSFER_ERR_RESPONSE;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    fclose(fp);
    return status;
}

TransferStatus transfer_download(const char *base_url, const char *code,
                                 const char *out_path,
                                 transfer_progress_cb cb, void *userdata)
{
    FILE *fp = fopen(out_path, "wb");
    if (!fp) return TRANSFER_ERR_OPEN_FILE;

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(fp); return TRANSFER_ERR_INIT; }

    char url[1024];
    build_url(url, sizeof(url), base_url, code);

    ProgressCtx pc = { cb, userdata };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &pc);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "kyber-zip/1.0");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L); /* treat 4xx/5xx as error */

    CURLcode rc = curl_easy_perform(curl);

    TransferStatus status = TRANSFER_OK;
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (rc != CURLE_OK) {
        /* With FAILONERROR, an HTTP error surfaces as CURLE_HTTP_RETURNED_ERROR. */
        status = (rc == CURLE_HTTP_RETURNED_ERROR)
            ? TRANSFER_ERR_HTTP : map_curl_error(rc);
    }

    curl_easy_cleanup(curl);
    fclose(fp);

    /* On failure, don't leave a partial/empty output file behind. */
    if (status != TRANSFER_OK) {
        remove(out_path);
    }
    return status;
}

const char *transfer_status_str(TransferStatus s)
{
    switch (s) {
        case TRANSFER_OK:            return "OK";
        case TRANSFER_ERR_INIT:      return "Failed to initialize network layer";
        case TRANSFER_ERR_OPEN_FILE: return "Could not open local file";
        case TRANSFER_ERR_NETWORK:   return "Network/connection error";
        case TRANSFER_ERR_HTTP:      return "Server returned an error (code expired or invalid?)";
        case TRANSFER_ERR_RESPONSE:  return "Unexpected server response";
        case TRANSFER_ERR_CANCELED:  return "Transfer canceled";
        default:                     return "Unknown error";
    }
}
