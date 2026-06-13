#include "gui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* On Windows, include windows.h BEFORE raylib with conflicting symbols disabled */
#ifdef _WIN32
#define NOGDI
#define NOUSER
#define NOMMSYSTEM
#define MMNOSOUND
#define NOMB
#include <windows.h>
#undef near
#undef far
#endif

#include "raylib.h"

/* raygui 4.5 calls TextToFloat() but only defines it under RAYGUI_STANDALONE,
 * and raylib 5.0 does not provide it. Supply a shim. */
static float TextToFloat(const char *text)
{
    return (text != NULL) ? (float)atof(text) : 0.0f;
}

#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

#include "tinyfiledialogs.h"
#include "transfer.h"

/* Force discrete GPU on NVIDIA Optimus / AMD switchable graphics.
 * Must come AFTER raylib includes to avoid windows.h symbol clashes. */
#ifdef _WIN32
__declspec(dllexport) unsigned long NvOptimusEnablement = 1;
__declspec(dllexport) unsigned long AmdPowerXpressRequestHighPerformance = 1;
#endif

/* Color scheme */
#define BG_COLOR       (Color){ 24,  26,  31, 255 }
#define PANEL_COLOR    (Color){ 34,  37,  44, 255 }
#define PANEL_HI_COLOR (Color){ 44,  48,  57, 255 }
#define ACCENT_COLOR   (Color){ 90, 156, 248, 255 }
#define BORDER_COLOR   (Color){ 58,  62,  72, 255 }
#define SUCCESS_COLOR  (Color){ 72, 196,  96, 255 }
#define ERROR_COLOR    (Color){232,  82,  82, 255 }
#define TEXT_COLOR     (Color){236, 238, 242, 255 }
#define DIM_TEXT_COLOR (Color){150, 156, 168, 255 }

/* Layout constants */
#define TOOLBAR_HEIGHT   50
#define STATUSBAR_HEIGHT 30
#define SIDEBAR_WIDTH   220
#define PADDING          10
#define BTN_WIDTH       100
#define BTN_HEIGHT       30

/* App font.
 * The atlas is baked at FONT_LOAD_SIZE (a multiple of the on-screen size) so
 * that glyphs stay crisp when raygui/DrawTextEx scale them down to the smaller
 * sizes the UI actually requests. Baking at the display size made small text
 * (11-13px) look soft and hard to read. */
static Font g_font = { 0 };
#define FONT_SIZE       18   /* default on-screen UI size            */
#define FONT_SIZE_SMALL 15   /* smallest size used anywhere          */
#define FONT_LOAD_SIZE  (FONT_SIZE * 3)  /* high-res atlas for sharp scaling */

/* Draw text with the loaded TTF font */
static void DrawAppText(const char *text, int x, int y, int size, Color color)
{
    if (g_font.texture.id > 0) {
        DrawTextEx(g_font, text, (Vector2){ (float)x, (float)y },
                   (float)size, 1.0f, color);
    } else {
        DrawText(text, x, y, size, color);
    }
}

static int MeasureAppText(const char *text, int size)
{
    if (g_font.texture.id > 0) {
        Vector2 v = MeasureTextEx(g_font, text, (float)size, 1.0f);
        return (int)v.x;
    }
    return MeasureText(text, size);
}

/* ---------- Forward declarations ---------- */

static void draw_toolbar(GuiContext *ctx);
static void draw_sidebar(GuiContext *ctx);
static void draw_file_list(GuiContext *ctx);
static void draw_statusbar(GuiContext *ctx);
static void draw_key_manager(GuiContext *ctx);
static void draw_progress_overlay(GuiContext *ctx);
static void draw_message_dialog(GuiContext *ctx);
static void draw_context_menu(GuiContext *ctx);
static void draw_receive_dialog(GuiContext *ctx);
static void draw_encrypt_confirm(GuiContext *ctx);
static void draw_send_confirm(GuiContext *ctx);
static void start_send_upload(GuiContext *ctx);
static void handle_drop(GuiContext *ctx);
static void handle_keyboard(GuiContext *ctx);

static void action_open_archive(GuiContext *ctx);
static void action_encrypt(GuiContext *ctx);
static void action_decrypt(GuiContext *ctx);
static void update_encrypt(GuiContext *ctx);
static void action_add_files(GuiContext *ctx);
static void action_add_folder(GuiContext *ctx);
static void action_send(GuiContext *ctx);
static void update_transfer(GuiContext *ctx);

static void relay_url_load(GuiContext *ctx);
static void relay_url_save(GuiContext *ctx);

static void gui_show_message(GuiContext *ctx, const char *msg, bool is_error);

/* ---------- Progress callback bridge ---------- */

static GuiContext *g_gui_ctx = NULL;

static void gui_progress_cb(uint32_t current, uint32_t total,
                             const char *filename, void *userdata)
{
    (void)userdata;
    GuiContext *ctx = g_gui_ctx;
    if (!ctx) return;
    ctx->progress = (total > 0) ? (float)current / (float)total : 0.0f;
    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "[%u/%u] %s", current, total, filename ? filename : "");
}

/* ---------- Helper: is path a directory ---------- */

static bool path_is_dir(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) && (st.st_mode & S_IFDIR);
}

/* ---------- Pending file helpers ---------- */

static void add_pending_one(GuiContext *ctx, const char *path)
{
    if (ctx->pending_count >= ctx->pending_capacity) {
        ctx->pending_capacity *= 2;
        ctx->pending_files = realloc(ctx->pending_files,
                                     ctx->pending_capacity * sizeof(char *));
    }
    ctx->pending_files[ctx->pending_count] = strdup(path);
    ctx->pending_count++;
}

#ifdef _WIN32
static void add_pending_dir(GuiContext *ctx, const char *dirpath)
{
    char search[1024];
    snprintf(search, sizeof(search), "%s\\*", dirpath);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dirpath, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            add_pending_dir(ctx, full);
        } else {
            add_pending_one(ctx, full);
        }
    } while (FindNextFileA(h, &fd) != 0);
    FindClose(h);
}
#else
#include <dirent.h>
static void add_pending_dir(GuiContext *ctx, const char *dirpath)
{
    DIR *dir = opendir(dirpath);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dirpath, ent->d_name);
        if (path_is_dir(full)) {
            add_pending_dir(ctx, full);
        } else {
            add_pending_one(ctx, full);
        }
    }
    closedir(dir);
}
#endif

static void add_pending_path(GuiContext *ctx, const char *path)
{
    if (path_is_dir(path)) {
        add_pending_dir(ctx, path);
    } else {
        add_pending_one(ctx, path);
    }
}

static void remove_pending(GuiContext *ctx, int index)
{
    if (index < 0 || (uint32_t)index >= ctx->pending_count) return;
    free(ctx->pending_files[index]);
    for (uint32_t i = (uint32_t)index; i < ctx->pending_count - 1; i++) {
        ctx->pending_files[i] = ctx->pending_files[i + 1];
    }
    ctx->pending_count--;
    ctx->pending_files[ctx->pending_count] = NULL;
    if (ctx->selected_file >= (int)ctx->pending_count) {
        ctx->selected_file = (int)ctx->pending_count - 1;
    }
}

/* ---------- Relay URL persistence ---------- */

/* The relay base URL lives next to the keystore in %APPDATA%\kyber-zip. */
static bool relay_config_path(char *out, size_t out_size)
{
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (!appdata) return false;
    snprintf(out, out_size, "%s\\kyber-zip\\relay.txt", appdata);
#else
    const char *home = getenv("HOME");
    if (!home) return false;
    snprintf(out, out_size, "%s/.kyber-zip/relay.txt", home);
#endif
    return true;
}

static void relay_url_load(GuiContext *ctx)
{
    char path[1024];
    if (!relay_config_path(path, sizeof(path))) return;

    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    size_t n = fread(ctx->relay_url, 1, sizeof(ctx->relay_url) - 1, fp);
    fclose(fp);
    ctx->relay_url[n] = '\0';

    /* Trim trailing whitespace/newlines. */
    while (n > 0) {
        char c = ctx->relay_url[n - 1];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            ctx->relay_url[--n] = '\0';
        } else {
            break;
        }
    }
}

static void relay_url_save(GuiContext *ctx)
{
    char path[1024];
    if (!relay_config_path(path, sizeof(path))) return;
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fputs(ctx->relay_url, fp);
    fclose(fp);
}

/* ---------- Background transfer worker ---------- */

/* Progress callback invoked from the worker thread. Writing a double that the
 * main thread reads is a benign race for a progress bar. Returning non-zero
 * would abort; we never cancel here. */
static int transfer_progress_bridge(double fraction, void *userdata)
{
    GuiContext *ctx = (GuiContext *)userdata;
    if (fraction >= 0.0) ctx->transfer_progress = fraction;
    /* Returning false aborts the transfer (curl -> CURLE_ABORTED_BY_CALLBACK). */
    return ctx->transfer_cancel ? 0 : 1;
}

#ifdef _WIN32
static DWORD WINAPI transfer_worker(LPVOID arg)
{
    GuiContext *ctx = (GuiContext *)arg;
    TransferStatus s;
    if (ctx->transfer_kind == 0) {
        s = transfer_upload(ctx->relay_url, ctx->transfer_path,
                            ctx->transfer_code, sizeof(ctx->transfer_code),
                            transfer_progress_bridge, ctx);
    } else {
        s = transfer_download(ctx->relay_url, ctx->transfer_code,
                              ctx->transfer_path,
                              transfer_progress_bridge, ctx);
    }
    ctx->transfer_status = (int)s;
    ctx->transfer_done = 1;
    return 0;
}
#endif

/* Kick off a transfer on a background thread. kind: 0 = upload, 1 = download. */
static void start_transfer(GuiContext *ctx, int kind)
{
    ctx->transfer_kind = kind;
    ctx->transfer_progress = 0.0;
    ctx->transfer_done = 0;
    ctx->transfer_status = 0;
    ctx->transfer_cancel = 0;
    ctx->transfer_active = true;
    ctx->operation_active = true;
    ctx->progress = 0.0f;
    snprintf(ctx->status_text, sizeof(ctx->status_text),
             kind == 0 ? "Uploading archive..." : "Downloading archive...");

#ifdef _WIN32
    ctx->transfer_thread = CreateThread(NULL, 0, transfer_worker, ctx, 0, NULL);
    if (!ctx->transfer_thread) {
        ctx->transfer_active = false;
        ctx->operation_active = false;
        gui_show_message(ctx, "Failed to start transfer thread.", true);
    }
#else
    /* Non-Windows fallback: run synchronously (UI blocks for the transfer). */
    TransferStatus s;
    if (kind == 0) {
        s = transfer_upload(ctx->relay_url, ctx->transfer_path,
                            ctx->transfer_code, sizeof(ctx->transfer_code),
                            transfer_progress_bridge, ctx);
    } else {
        s = transfer_download(ctx->relay_url, ctx->transfer_code,
                              ctx->transfer_path, transfer_progress_bridge, ctx);
    }
    ctx->transfer_status = (int)s;
    ctx->transfer_done = 1;
#endif
}

/* ---------- GUI lifecycle ---------- */

void gui_init(GuiContext *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->current_view = GUI_VIEW_MAIN;
    ctx->selected_param = MLKEM_768;
    ctx->compress_level = 6;
    ctx->selected_file = -1;
    ctx->selected_key = -1;
    ctx->pending_capacity = 64;
    ctx->pending_files = calloc(ctx->pending_capacity, sizeof(char *));

    snprintf(ctx->keygen_label, sizeof(ctx->keygen_label), "my-key");

    keystore_init(&ctx->keystore);

    /* Auto-select first key if available */
    if (ctx->keystore.count > 0) {
        ctx->selected_key = 0;
    }

    /* Load the saved relay URL (empty until the user sets one in Receive). */
    relay_url_load(ctx);

    snprintf(ctx->status_text, sizeof(ctx->status_text), "Ready");
}

void gui_shutdown(GuiContext *ctx)
{
#ifdef _WIN32
    /* If a transfer is still running, wait for it before tearing down the
     * context the worker thread is reading from. */
    if (ctx->transfer_thread) {
        WaitForSingleObject((HANDLE)ctx->transfer_thread, INFINITE);
        CloseHandle((HANDLE)ctx->transfer_thread);
        ctx->transfer_thread = NULL;
    }
#endif

    if (ctx->archive) {
        kyber_archive_free(ctx->archive);
        ctx->archive = NULL;
    }
    keystore_free(&ctx->keystore);

    for (uint32_t i = 0; i < ctx->pending_count; i++) {
        free(ctx->pending_files[i]);
    }
    free(ctx->pending_files);
}

void gui_update(GuiContext *ctx)
{
    handle_drop(ctx);
    handle_keyboard(ctx);

    /* Drive async encrypt operation */
    if (ctx->encrypt_active) {
        update_encrypt(ctx);
    }

    /* Drive background transfer (upload/download) */
    if (ctx->transfer_active) {
        update_transfer(ctx);
    }

    /* Mouse wheel scrolling in file list area */
    int lx = SIDEBAR_WIDTH + 1;
    int ly = TOOLBAR_HEIGHT + 1;
    int lw = GUI_WIDTH - SIDEBAR_WIDTH - 1;
    int lh = GUI_HEIGHT - TOOLBAR_HEIGHT - STATUSBAR_HEIGHT - 1;

    Vector2 mouse = GetMousePosition();
    Rectangle list_area = { (float)lx, (float)ly, (float)lw, (float)lh };
    if (CheckCollisionPointRec(mouse, list_area)) {
        int wheel = (int)GetMouseWheelMove();
        if (wheel != 0) {
            ctx->scroll_offset -= wheel * 3;
            if (ctx->scroll_offset < 0) ctx->scroll_offset = 0;

            /* Clamp to max */
            uint32_t total = 0;
            if (ctx->archive && ctx->archive->entries)
                total = ctx->archive->file_count;
            else
                total = ctx->pending_count;

            int visible_rows = (lh - 28) / 24;
            int max_scroll = (int)total - visible_rows;
            if (max_scroll < 0) max_scroll = 0;
            if (ctx->scroll_offset > max_scroll)
                ctx->scroll_offset = max_scroll;
        }
    }
}

void gui_draw(GuiContext *ctx)
{
    ClearBackground(BG_COLOR);

    draw_toolbar(ctx);
    draw_sidebar(ctx);
    draw_file_list(ctx);
    draw_statusbar(ctx);

    if (ctx->show_keymgr) {
        draw_key_manager(ctx);
    }

    if (ctx->show_receive) {
        draw_receive_dialog(ctx);
    }

    if (ctx->show_encrypt_confirm) {
        draw_encrypt_confirm(ctx);
    }

    if (ctx->show_send_confirm) {
        draw_send_confirm(ctx);
    }

    if (ctx->show_ctx_menu) {
        draw_context_menu(ctx);
    }

    if (ctx->show_message) {
        draw_message_dialog(ctx);
    }

    if (ctx->operation_active) {
        draw_progress_overlay(ctx);
    }
}

/* ---------- Message dialog ---------- */

static void gui_show_message(GuiContext *ctx, const char *msg, bool is_error)
{
    strncpy(ctx->message_text, msg, sizeof(ctx->message_text) - 1);
    ctx->message_is_error = is_error;
    ctx->show_message = true;
}

static void draw_message_dialog(GuiContext *ctx)
{
    int dw = 420, dh = 120;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);

    Color border = ctx->message_is_error ? ERROR_COLOR : SUCCESS_COLOR;
    DrawRectangleLines(dx, dy, dw, dh, border);

    const char *title = ctx->message_is_error ? "Error" : "Success";
    DrawAppText(title, dx + PADDING, dy + PADDING, FONT_SIZE, border);
    DrawAppText(ctx->message_text, dx + PADDING, dy + 40, FONT_SIZE, TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + dw - 70, dy + dh - 38, 60, 28 }, "OK")) {
        ctx->show_message = false;
    }
}

/* ---------- Receive dialog ---------- */

static void draw_receive_dialog(GuiContext *ctx)
{
    int dw = 480, dh = 230;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);
    DrawRectangleLines(dx, dy, dw, dh, ACCENT_COLOR);

    DrawAppText("Receive File", dx + PADDING, dy + PADDING, FONT_SIZE, TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + dw - 30, dy + 5, 24, 24 }, "X")) {
        ctx->show_receive = false;
    }

    int x = dx + PADDING;
    int w = dw - 2 * PADDING;
    int y = dy + 44;

    /* Relay URL */
    DrawAppText("Relay URL", x, y, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
    y += 20;
    if (GuiTextBox((Rectangle){ x, y, w, BTN_HEIGHT },
                   ctx->relay_url, sizeof(ctx->relay_url), ctx->relay_url_edit)) {
        ctx->relay_url_edit = !ctx->relay_url_edit;
    }
    y += BTN_HEIGHT + PADDING;

    /* Claim code */
    DrawAppText("Claim Code", x, y, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
    y += 20;
    if (GuiTextBox((Rectangle){ x, y, w, BTN_HEIGHT },
                   ctx->recv_code, sizeof(ctx->recv_code), ctx->recv_code_edit)) {
        ctx->recv_code_edit = !ctx->recv_code_edit;
    }
    y += BTN_HEIGHT + PADDING + 4;

    DrawAppText("Paste the code shared with you, then Download.",
                x, y, FONT_SIZE_SMALL, DIM_TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + dw - 130 - PADDING, dy + dh - BTN_HEIGHT - PADDING,
                               130, BTN_HEIGHT }, "Download")) {
        /* Trim surrounding whitespace from the pasted code. */
        char code[64];
        const char *p = ctx->recv_code;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        strncpy(code, p, sizeof(code) - 1);
        code[sizeof(code) - 1] = '\0';
        size_t cl = strlen(code);
        while (cl > 0 && (code[cl-1]==' '||code[cl-1]=='\t'||code[cl-1]=='\n'||code[cl-1]=='\r'))
            code[--cl] = '\0';

        if (!ctx->relay_url[0]) {
            gui_show_message(ctx, "Enter a relay URL first.", true);
            return;
        }
        if (cl == 0) {
            gui_show_message(ctx, "Enter a claim code.", true);
            return;
        }

        relay_url_save(ctx);

        const char *filters[] = { "*.kyz" };
        const char *outpath = tinyfd_saveFileDialog(
            "Save Received Archive As", "received.kyz", 1, filters,
            "Kyber-Zip Archives (*.kyz)");
        if (!outpath) return;

        strncpy(ctx->transfer_code, code, sizeof(ctx->transfer_code) - 1);
        ctx->transfer_code[sizeof(ctx->transfer_code) - 1] = '\0';
        strncpy(ctx->transfer_path, outpath, sizeof(ctx->transfer_path) - 1);
        ctx->transfer_path[sizeof(ctx->transfer_path) - 1] = '\0';

        ctx->show_receive = false;
        ctx->recv_code[0] = '\0';
        g_gui_ctx = ctx;
        start_transfer(ctx, 1 /* download */);
    }
}

/* ---------- Unverified-recipient warning ---------- */

static void draw_encrypt_confirm(GuiContext *ctx)
{
    int dw = 460, dh = 190;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);
    DrawRectangleLines(dx, dy, dw, dh, ERROR_COLOR);

    const char *label = (ctx->selected_key >= 0 &&
                         (uint32_t)ctx->selected_key < ctx->keystore.count)
                        ? ctx->keystore.entries[ctx->selected_key].label : "?";

    DrawAppText("Unverified recipient", dx + PADDING, dy + PADDING, FONT_SIZE, ERROR_COLOR);

    char l1[160];
    snprintf(l1, sizeof(l1), "Key '%s' has not been verified.", label);
    DrawAppText(l1, dx + PADDING, dy + 42, FONT_SIZE_SMALL, TEXT_COLOR);
    DrawAppText("Confirm its fingerprint in Key Manager before trusting it,",
                dx + PADDING, dy + 64, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
    DrawAppText("or an impostor's key could be substituted for the recipient's.",
                dx + PADDING, dy + 84, FONT_SIZE_SMALL, DIM_TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + PADDING, dy + dh - BTN_HEIGHT - PADDING,
                               150, BTN_HEIGHT }, "Open Key Manager")) {
        ctx->show_encrypt_confirm = false;
        ctx->show_keymgr = true;
    }
    if (GuiButton((Rectangle){ dx + dw - 110 - PADDING, dy + dh - BTN_HEIGHT - PADDING,
                               110, BTN_HEIGHT }, "Encrypt Anyway")) {
        ctx->show_encrypt_confirm = false;
        ctx->encrypt_confirmed = true;
        action_encrypt(ctx);
    }
    if (GuiButton((Rectangle){ dx + dw - 110 - PADDING - 90 - PADDING,
                               dy + dh - BTN_HEIGHT - PADDING, 90, BTN_HEIGHT }, "Cancel")) {
        ctx->show_encrypt_confirm = false;
    }
}

static void draw_send_confirm(GuiContext *ctx)
{
    int dw = 460, dh = 190;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);
    DrawRectangleLines(dx, dy, dw, dh, ERROR_COLOR);

    const char *label = (ctx->selected_key >= 0 &&
                         (uint32_t)ctx->selected_key < ctx->keystore.count)
                        ? ctx->keystore.entries[ctx->selected_key].label : "?";

    DrawAppText("Send to unverified recipient?", dx + PADDING, dy + PADDING, FONT_SIZE, ERROR_COLOR);

    char l1[160];
    snprintf(l1, sizeof(l1), "Recipient key '%s' has not been verified.", label);
    DrawAppText(l1, dx + PADDING, dy + 42, FONT_SIZE_SMALL, TEXT_COLOR);
    DrawAppText("Uploading shares this archive via the relay. Confirm the key's",
                dx + PADDING, dy + 64, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
    DrawAppText("fingerprint in Key Manager before sending to it.",
                dx + PADDING, dy + 84, FONT_SIZE_SMALL, DIM_TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + PADDING, dy + dh - BTN_HEIGHT - PADDING,
                               150, BTN_HEIGHT }, "Open Key Manager")) {
        ctx->show_send_confirm = false;
        ctx->show_keymgr = true;
    }
    if (GuiButton((Rectangle){ dx + dw - 110 - PADDING, dy + dh - BTN_HEIGHT - PADDING,
                               110, BTN_HEIGHT }, "Send Anyway")) {
        ctx->show_send_confirm = false;
        start_send_upload(ctx);
    }
    if (GuiButton((Rectangle){ dx + dw - 110 - PADDING - 90 - PADDING,
                               dy + dh - BTN_HEIGHT - PADDING, 90, BTN_HEIGHT }, "Cancel")) {
        ctx->show_send_confirm = false;
    }
}

/* ---------- Keyboard handling ---------- */

static void handle_keyboard(GuiContext *ctx)
{
    /* Don't process keys when dialogs are open */
    if (ctx->show_keymgr || ctx->show_receive || ctx->show_encrypt_confirm ||
        ctx->show_send_confirm || ctx->show_message || ctx->operation_active) return;

    /* Delete/Backspace: remove selected pending file */
    if (IsKeyPressed(KEY_DELETE) || IsKeyPressed(KEY_BACKSPACE)) {
        if (!ctx->archive && ctx->selected_file >= 0 &&
            (uint32_t)ctx->selected_file < ctx->pending_count) {
            remove_pending(ctx, ctx->selected_file);
            snprintf(ctx->status_text, sizeof(ctx->status_text),
                     "%u file(s) ready", ctx->pending_count);
        }
    }

    /* Up/Down arrow: move selection */
    if (IsKeyPressed(KEY_UP) && ctx->selected_file > 0) {
        ctx->selected_file--;
    }
    if (IsKeyPressed(KEY_DOWN)) {
        uint32_t max_idx = 0;
        if (ctx->archive && ctx->archive->entries)
            max_idx = ctx->archive->file_count;
        else
            max_idx = ctx->pending_count;

        if (ctx->selected_file < (int)max_idx - 1) {
            ctx->selected_file++;
        }
    }

    /* Escape: close context menu */
    if (IsKeyPressed(KEY_ESCAPE)) {
        ctx->show_ctx_menu = false;
    }
}

/* ---------- Context menu ---------- */

static void draw_context_menu(GuiContext *ctx)
{
    int mx = ctx->ctx_menu_x;
    int my = ctx->ctx_menu_y;
    int mw = 160;
    int item_h = 24;
    int item_count = 0;

    bool is_archive = (ctx->archive && ctx->archive->entries);
    bool is_pending = (!ctx->archive && ctx->pending_count > 0);

    if (is_archive) item_count = 2;      /* Extract File, Extract All */
    else if (is_pending) item_count = 1;  /* Remove */
    else { ctx->show_ctx_menu = false; return; }

    int mh = item_count * item_h + 4;

    /* Clamp to window bounds */
    if (mx + mw > GUI_WIDTH) mx = GUI_WIDTH - mw;
    if (my + mh > GUI_HEIGHT) my = GUI_HEIGHT - mh;

    DrawRectangle(mx, my, mw, mh, PANEL_COLOR);
    DrawRectangleLines(mx, my, mw, mh, ACCENT_COLOR);

    int y = my + 2;

    if (is_pending) {
        Rectangle btn = { (float)mx + 2, (float)y, (float)(mw - 4), (float)item_h };
        if (GuiButton(btn, "  Remove")) {
            remove_pending(ctx, ctx->ctx_menu_target);
            ctx->show_ctx_menu = false;
            snprintf(ctx->status_text, sizeof(ctx->status_text),
                     "%u file(s) ready", ctx->pending_count);
        }
    }

    if (is_archive) {
        /* Extract single file */
        Rectangle btn1 = { (float)mx + 2, (float)y, (float)(mw - 4), (float)item_h };
        if (GuiButton(btn1, "  Extract File")) {
            ctx->show_ctx_menu = false;

            if (ctx->ctx_menu_target >= 0 &&
                (uint32_t)ctx->ctx_menu_target < ctx->archive->file_count) {
                const char *outdir = tinyfd_selectFolderDialog("Extract To", "");
                if (outdir) {
                    KyberError err = kyber_archive_extract_file(
                        ctx->archive, (uint32_t)ctx->ctx_menu_target, outdir);
                    if (err != KYBER_OK) {
                        gui_show_message(ctx, kyber_error_str(err), true);
                    } else {
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Extracted: %s",
                                 ctx->archive->entries[ctx->ctx_menu_target].name);
                        gui_show_message(ctx, msg, false);
                    }
                }
            }
        }
        y += item_h;

        /* Extract all */
        Rectangle btn2 = { (float)mx + 2, (float)y, (float)(mw - 4), (float)item_h };
        if (GuiButton(btn2, "  Extract All")) {
            ctx->show_ctx_menu = false;

            const char *outdir = tinyfd_selectFolderDialog("Extract All To", "");
            if (outdir) {
                KyberError err = kyber_archive_extract_all(ctx->archive, outdir);
                if (err != KYBER_OK) {
                    gui_show_message(ctx, kyber_error_str(err), true);
                } else {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Extracted %u files to: %s",
                             ctx->archive->file_count, outdir);
                    gui_show_message(ctx, msg, false);
                }
            }
        }
    }

    /* Click outside closes menu */
    if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        Vector2 mouse = GetMousePosition();
        Rectangle menu_rect = { (float)mx, (float)my, (float)mw, (float)mh };
        if (!CheckCollisionPointRec(mouse, menu_rect)) {
            ctx->show_ctx_menu = false;
        }
    }
}

/* ---------- Drag & Drop ---------- */

static void handle_drop(GuiContext *ctx)
{
    if (!IsFileDropped()) return;

    FilePathList dropped = LoadDroppedFiles();

    for (unsigned int i = 0; i < dropped.count; i++) {
        /* Check if this is a .kyz archive being dropped */
        size_t len = strlen(dropped.paths[i]);
        if (len > 4 && strcmp(dropped.paths[i] + len - 4, ".kyz") == 0) {
            /* Open it as an archive instead of adding as a file */
            if (ctx->archive) {
                kyber_archive_free(ctx->archive);
                ctx->archive = NULL;
            }
            ctx->scroll_offset = 0;
            ctx->selected_file = -1;
            KyberError err = kyber_archive_open(&ctx->archive, dropped.paths[i]);
            if (err != KYBER_OK) {
                gui_show_message(ctx, kyber_error_str(err), true);
            } else {
                strncpy(ctx->current_archive_path, dropped.paths[i],
                        sizeof(ctx->current_archive_path) - 1);
                ctx->current_archive_path[sizeof(ctx->current_archive_path) - 1] = '\0';
                snprintf(ctx->status_text, sizeof(ctx->status_text),
                         "Opened: %s (%u files) — select key and click Decrypt",
                         dropped.paths[i], ctx->archive->file_count);
            }
            UnloadDroppedFiles(dropped);
            return;
        }

        /* Add file or recursively enumerate directory */
        add_pending_path(ctx, dropped.paths[i]);
    }

    UnloadDroppedFiles(dropped);
    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "%u file(s) ready — select key and click Encrypt", ctx->pending_count);
}

/* ---------- Actions ---------- */

static void action_open_archive(GuiContext *ctx)
{
    const char *filters[] = { "*.kyz" };
    const char *path = tinyfd_openFileDialog(
        "Open Archive", "", 1, filters, "Kyber-Zip Archives (*.kyz)", 0);

    if (!path) return;

    if (ctx->archive) {
        kyber_archive_free(ctx->archive);
        ctx->archive = NULL;
    }

    /* Clear pending files when opening an archive */
    for (uint32_t i = 0; i < ctx->pending_count; i++) {
        free(ctx->pending_files[i]);
        ctx->pending_files[i] = NULL;
    }
    ctx->pending_count = 0;
    ctx->scroll_offset = 0;
    ctx->selected_file = -1;

    KyberError err = kyber_archive_open(&ctx->archive, path);
    if (err != KYBER_OK) {
        gui_show_message(ctx, kyber_error_str(err), true);
        return;
    }

    strncpy(ctx->current_archive_path, path, sizeof(ctx->current_archive_path) - 1);
    ctx->current_archive_path[sizeof(ctx->current_archive_path) - 1] = '\0';

    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "Opened: %s (%u files) — select key and click Decrypt",
             path, ctx->archive->file_count);
}

static void action_add_files(GuiContext *ctx)
{
    const char *paths = tinyfd_openFileDialog(
        "Add Files", "", 0, NULL, "All Files", 1 /* multi-select */);

    if (!paths) return;

    /* tinyfd returns '|'-separated paths on multi-select */
    char *buf = strdup(paths);
    char *tok = strtok(buf, "|");
    while (tok) {
        if (ctx->pending_count >= ctx->pending_capacity) {
            ctx->pending_capacity *= 2;
            ctx->pending_files = realloc(ctx->pending_files,
                                         ctx->pending_capacity * sizeof(char *));
        }
        ctx->pending_files[ctx->pending_count] = strdup(tok);
        ctx->pending_count++;
        tok = strtok(NULL, "|");
    }
    free(buf);

    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "%u file(s) ready", ctx->pending_count);
}

static void action_add_folder(GuiContext *ctx)
{
    const char *dir = tinyfd_selectFolderDialog("Add Folder", "");
    if (!dir) return;

    add_pending_path(ctx, dir);

    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "%u file(s) ready", ctx->pending_count);
}

static void action_encrypt(GuiContext *ctx)
{
    if (ctx->pending_count == 0) {
        gui_show_message(ctx, "No files to encrypt. Drag files or use Add Files.", true);
        return;
    }

    if (ctx->selected_key < 0 || (uint32_t)ctx->selected_key >= ctx->keystore.count) {
        gui_show_message(ctx, "No recipient key selected. Use the sidebar to select one.", true);
        return;
    }

    /* Warn before encrypting to a recipient whose key hasn't been verified
     * out-of-band — unless the user already chose to proceed anyway. */
    if (!ctx->encrypt_confirmed &&
        !keystore_is_verified(&ctx->keystore, (uint32_t)ctx->selected_key)) {
        ctx->show_encrypt_confirm = true;
        return;
    }
    ctx->encrypt_confirmed = false;

    KeystoreEntry *key = &ctx->keystore.entries[ctx->selected_key];

    /* Ask where to save */
    const char *filters[] = { "*.kyz" };
    const char *outpath = tinyfd_saveFileDialog(
        "Save Archive As", "archive.kyz", 1, filters, "Kyber-Zip Archives (*.kyz)");

    if (!outpath) return;

    /* Create archive — use the key's own parameter set to avoid mismatch */
    KyberArchive *arc = NULL;
    KyberError err = kyber_archive_create(&arc, key->param,
                                          key->public_key, key->public_key_len);
    if (err != KYBER_OK) {
        gui_show_message(ctx, kyber_error_str(err), true);
        return;
    }

    /* Stage all pending files/directories into the archive */
    for (uint32_t i = 0; i < ctx->pending_count; i++) {
        const char *arcname = ctx->pending_files[i];
        const char *sep = strrchr(arcname, '/');
        const char *bsep = strrchr(arcname, '\\');
        if (bsep && (!sep || bsep > sep)) sep = bsep;
        if (sep) arcname = sep + 1;

        if (path_is_dir(ctx->pending_files[i])) {
            err = kyber_archive_add_dir(arc, ctx->pending_files[i],
                                        ctx->compress_level);
        } else {
            err = kyber_archive_add_file(arc, ctx->pending_files[i], arcname,
                                         ctx->compress_level);
        }

        if (err != KYBER_OK) {
            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "%s: %s",
                     kyber_error_str(err), ctx->pending_files[i]);
            kyber_archive_free(arc);
            gui_show_message(ctx, errmsg, true);
            return;
        }
    }

    /* Begin incremental write — opens the output file and writes the header */
    KyberError begin_err = kyber_archive_write_begin(arc, outpath);
    if (begin_err != KYBER_OK) {
        char errmsg[512];
        snprintf(errmsg, sizeof(errmsg), "Write failed: %s (errno %d: %s)\nPath: %s",
                 kyber_error_str(begin_err), errno, strerror(errno), outpath);
        kyber_archive_free(arc);
        gui_show_message(ctx, errmsg, true);
        return;
    }

    /* Set up async encrypt state — processing happens in update_encrypt() */
    ctx->encrypt_active = true;
    ctx->encrypt_arc = arc;
    strncpy(ctx->encrypt_outpath, outpath, sizeof(ctx->encrypt_outpath) - 1);
    ctx->encrypt_outpath[sizeof(ctx->encrypt_outpath) - 1] = '\0';
    ctx->encrypt_index = 0;
    ctx->encrypt_writing = false;

    ctx->operation_active = true;
    ctx->progress = 0.0f;
    g_gui_ctx = ctx;

    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "Encrypting: 0/%u files", arc->file_count);
}

/* Process one file per frame so the progress bar redraws between files */
static void update_encrypt(GuiContext *ctx)
{
    KyberArchive *arc = ctx->encrypt_arc;

    if (ctx->encrypt_writing) {
        /* All files processed — finalize the archive */
        snprintf(ctx->status_text, sizeof(ctx->status_text), "Finalizing archive...");
        ctx->progress = 1.0f;

        KyberError err = kyber_archive_write_finish(arc);

        ctx->encrypt_active = false;
        ctx->operation_active = false;
        g_gui_ctx = NULL;

        if (err != KYBER_OK) {
            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "Write failed: %s (errno %d: %s)\nPath: %s",
                     kyber_error_str(err), errno, strerror(errno), ctx->encrypt_outpath);
            kyber_archive_free(arc);
            ctx->encrypt_arc = NULL;
            gui_show_message(ctx, errmsg, true);
            return;
        }

        /* Clear pending files */
        for (uint32_t i = 0; i < ctx->pending_count; i++) {
            free(ctx->pending_files[i]);
            ctx->pending_files[i] = NULL;
        }
        ctx->pending_count = 0;

        /* Show the newly created archive */
        if (ctx->archive) kyber_archive_free(ctx->archive);
        ctx->archive = arc;
        ctx->encrypt_arc = NULL;

        /* Remember its path so "Send" can upload it directly. */
        strncpy(ctx->current_archive_path, ctx->encrypt_outpath,
                sizeof(ctx->current_archive_path) - 1);
        ctx->current_archive_path[sizeof(ctx->current_archive_path) - 1] = '\0';

        char msg[512];
        snprintf(msg, sizeof(msg), "Archive created: %s (%u files)",
                 ctx->encrypt_outpath, arc->file_count);
        gui_show_message(ctx, msg, false);
        snprintf(ctx->status_text, sizeof(ctx->status_text), "Archive saved.");
        return;
    }

    /* Process one file this frame */
    uint32_t i = ctx->encrypt_index;

    ctx->progress = (arc->file_count > 0)
        ? (float)i / (float)arc->file_count
        : 0.0f;

    if (i < arc->file_count) {
        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "[%u/%u] %s", i + 1, arc->file_count,
                 arc->staged[i].arcname);

        KyberError err = kyber_archive_write_next(arc, i);
        if (err != KYBER_OK) {
            ctx->encrypt_active = false;
            ctx->operation_active = false;
            g_gui_ctx = NULL;

            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "%s: %s",
                     kyber_error_str(err), arc->staged[i].arcname);

            /* Close and clean up the partial write */
            if (arc->write_fp) { fclose(arc->write_fp); arc->write_fp = NULL; }
            kyber_archive_free(arc);
            ctx->encrypt_arc = NULL;
            gui_show_message(ctx, errmsg, true);
            return;
        }

        ctx->encrypt_index++;
    }

    /* If we just processed the last file, finalize on next frame */
    if (ctx->encrypt_index >= arc->file_count) {
        ctx->encrypt_writing = true;
    }
}

static void action_decrypt(GuiContext *ctx)
{
    if (!ctx->archive) {
        gui_show_message(ctx, "No archive open. Use Open Archive or drag a .kyz file.", true);
        return;
    }

    if (ctx->selected_key < 0 || (uint32_t)ctx->selected_key >= ctx->keystore.count) {
        gui_show_message(ctx, "No key selected. Use the sidebar to select a private key.", true);
        return;
    }

    KeystoreEntry *key = &ctx->keystore.entries[ctx->selected_key];
    if (!key->has_secret) {
        gui_show_message(ctx, "Selected key has no private key. Cannot decrypt.", true);
        return;
    }

    /* Ask for output directory */
    const char *outdir = tinyfd_selectFolderDialog("Extract To", "");
    if (!outdir) return;

    /* Unlock */
    ctx->operation_active = true;
    ctx->progress = 0.0f;
    g_gui_ctx = ctx;

    snprintf(ctx->status_text, sizeof(ctx->status_text), "Decrypting archive...");

    KyberError err = kyber_archive_unlock(ctx->archive,
                                          key->secret_key, key->secret_key_len);
    if (err != KYBER_OK) {
        ctx->operation_active = false;
        g_gui_ctx = NULL;
        gui_show_message(ctx, kyber_error_str(err), true);
        return;
    }

    /* Extract all */
    kyber_archive_set_progress(ctx->archive, gui_progress_cb, NULL);

    err = kyber_archive_extract_all(ctx->archive, outdir);

    ctx->operation_active = false;
    g_gui_ctx = NULL;

    if (err != KYBER_OK) {
        gui_show_message(ctx, kyber_error_str(err), true);
        return;
    }

    char msg[512];
    snprintf(msg, sizeof(msg), "Extracted %u files to: %s",
             ctx->archive->file_count, outdir);
    gui_show_message(ctx, msg, false);
    snprintf(ctx->status_text, sizeof(ctx->status_text),
             "Extraction complete: %u files", ctx->archive->file_count);
}

/* ---------- Secure transfer actions ---------- */

static void action_send(GuiContext *ctx)
{
    if (!ctx->relay_url[0]) {
        gui_show_message(ctx,
            "No relay URL set. Open Receive and enter a relay address first.", true);
        ctx->show_receive = true;
        return;
    }

    /* Send the open/just-created archive if we have one on disk; otherwise let
     * the user pick a .kyz to send. */
    const char *path = NULL;
    if (ctx->current_archive_path[0]) {
        path = ctx->current_archive_path;
    } else {
        const char *filters[] = { "*.kyz" };
        path = tinyfd_openFileDialog(
            "Send Archive", "", 1, filters, "Kyber-Zip Archives (*.kyz)", 0);
        if (!path) return;
    }

    strncpy(ctx->transfer_path, path, sizeof(ctx->transfer_path) - 1);
    ctx->transfer_path[sizeof(ctx->transfer_path) - 1] = '\0';

    /* Gate on the selected recipient's verification status. The archive itself
     * only carries KEM ciphertext (not the recipient's public key), so the
     * selected key is the best available recipient signal. */
    if (ctx->selected_key >= 0 && (uint32_t)ctx->selected_key < ctx->keystore.count &&
        !keystore_is_verified(&ctx->keystore, (uint32_t)ctx->selected_key)) {
        ctx->show_send_confirm = true; /* transfer_path is already set */
        return;
    }

    start_send_upload(ctx);
}

/* Begin the upload of the already-resolved ctx->transfer_path. */
static void start_send_upload(GuiContext *ctx)
{
    g_gui_ctx = ctx;
    start_transfer(ctx, 0 /* upload */);
}

/* Poll the background transfer and finalize when it completes. */
static void update_transfer(GuiContext *ctx)
{
    /* Mirror worker progress into the shared overlay state each frame. */
    ctx->progress = (float)ctx->transfer_progress;
    if (ctx->transfer_cancel) {
        snprintf(ctx->status_text, sizeof(ctx->status_text), "Canceling...");
    } else if (ctx->transfer_kind == 0) {
        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "Uploading... %.0f%%", ctx->transfer_progress * 100.0);
    } else {
        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "Downloading... %.0f%%", ctx->transfer_progress * 100.0);
    }

    if (!ctx->transfer_done) return;

    /* Worker finished — reap the thread. */
#ifdef _WIN32
    if (ctx->transfer_thread) {
        WaitForSingleObject((HANDLE)ctx->transfer_thread, INFINITE);
        CloseHandle((HANDLE)ctx->transfer_thread);
        ctx->transfer_thread = NULL;
    }
#endif
    ctx->transfer_active = false;
    ctx->operation_active = false;
    g_gui_ctx = NULL;

    TransferStatus s = (TransferStatus)ctx->transfer_status;
    if (s == TRANSFER_ERR_CANCELED) {
        /* User-initiated — just note it in the status bar, no error dialog. */
        snprintf(ctx->status_text, sizeof(ctx->status_text), "Transfer canceled.");
        return;
    }
    if (s != TRANSFER_OK) {
        gui_show_message(ctx, transfer_status_str(s), true);
        snprintf(ctx->status_text, sizeof(ctx->status_text), "Transfer failed.");
        return;
    }

    if (ctx->transfer_kind == 0) {
        /* Upload done — surface the claim code and copy it to the clipboard. */
        SetClipboardText(ctx->transfer_code);
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Sent! Share this code (copied to clipboard):\n%s",
                 ctx->transfer_code);
        gui_show_message(ctx, msg, false);
        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "Upload complete — code %s copied to clipboard", ctx->transfer_code);
    } else {
        /* Download done — open the received file as the current archive. */
        if (ctx->archive) {
            kyber_archive_free(ctx->archive);
            ctx->archive = NULL;
        }
        ctx->scroll_offset = 0;
        ctx->selected_file = -1;

        KyberError err = kyber_archive_open(&ctx->archive, ctx->transfer_path);
        if (err != KYBER_OK) {
            gui_show_message(ctx, kyber_error_str(err), true);
            return;
        }
        strncpy(ctx->current_archive_path, ctx->transfer_path,
                sizeof(ctx->current_archive_path) - 1);
        ctx->current_archive_path[sizeof(ctx->current_archive_path) - 1] = '\0';

        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "Received: %s (%u files) — select key and click Decrypt",
                 ctx->transfer_path, ctx->archive->file_count);
    }
}

/* ---------- Toolbar ---------- */

static void draw_toolbar(GuiContext *ctx)
{
    DrawRectangle(0, 0, GUI_WIDTH, TOOLBAR_HEIGHT, PANEL_COLOR);
    DrawLine(0, TOOLBAR_HEIGHT, GUI_WIDTH, TOOLBAR_HEIGHT, BORDER_COLOR);

    int x = PADDING;
    int y = PADDING;

    if (GuiButton((Rectangle){ x, y, BTN_WIDTH, BTN_HEIGHT }, "New Archive")) {
        for (uint32_t i = 0; i < ctx->pending_count; i++) {
            free(ctx->pending_files[i]);
            ctx->pending_files[i] = NULL;
        }
        ctx->pending_count = 0;
        if (ctx->archive) {
            kyber_archive_free(ctx->archive);
            ctx->archive = NULL;
        }
        ctx->selected_file = -1;
        ctx->scroll_offset = 0;
        ctx->current_archive_path[0] = '\0';
        snprintf(ctx->status_text, sizeof(ctx->status_text),
                 "New archive — drag files or click Add Files");
    }
    x += BTN_WIDTH + PADDING;

    if (GuiButton((Rectangle){ x, y, BTN_WIDTH, BTN_HEIGHT }, "Open Archive")) {
        action_open_archive(ctx);
    }
    x += BTN_WIDTH + PADDING;

    if (GuiButton((Rectangle){ x, y, 80, BTN_HEIGHT }, "Add Files")) {
        action_add_files(ctx);
    }
    x += 80 + PADDING;

    if (GuiButton((Rectangle){ x, y, 80, BTN_HEIGHT }, "Add Folder")) {
        action_add_folder(ctx);
    }
    x += 80 + PADDING;

    if (GuiButton((Rectangle){ x, y, BTN_WIDTH, BTN_HEIGHT }, "Encrypt")) {
        action_encrypt(ctx);
    }
    x += BTN_WIDTH + PADDING;

    if (GuiButton((Rectangle){ x, y, BTN_WIDTH, BTN_HEIGHT }, "Decrypt")) {
        action_decrypt(ctx);
    }
    x += BTN_WIDTH + PADDING;

    if (GuiButton((Rectangle){ x, y, BTN_WIDTH, BTN_HEIGHT }, "Key Manager")) {
        ctx->show_keymgr = !ctx->show_keymgr;
    }
    x += BTN_WIDTH + PADDING;

    if (GuiButton((Rectangle){ x, y, 70, BTN_HEIGHT }, "Send")) {
        action_send(ctx);
    }
    x += 70 + PADDING;

    if (GuiButton((Rectangle){ x, y, 70, BTN_HEIGHT }, "Receive")) {
        ctx->show_receive = !ctx->show_receive;
    }
}

/* ---------- Sidebar (settings) ---------- */

static void draw_sidebar(GuiContext *ctx)
{
    int sx = 0;
    int sy = TOOLBAR_HEIGHT + 1;
    int sh = GUI_HEIGHT - TOOLBAR_HEIGHT - STATUSBAR_HEIGHT - 1;

    DrawRectangle(sx, sy, SIDEBAR_WIDTH, sh, PANEL_COLOR);
    DrawLine(SIDEBAR_WIDTH, sy, SIDEBAR_WIDTH, sy + sh, BORDER_COLOR);

    int y = sy + PADDING;
    int x = PADDING;
    int w = SIDEBAR_WIDTH - 2 * PADDING;

    /* Section: Algorithm */
    DrawAppText("ML-KEM Parameter Set", x, y, FONT_SIZE, DIM_TEXT_COLOR);
    y += 20;

    bool sel512  = (ctx->selected_param == MLKEM_512);
    bool sel768  = (ctx->selected_param == MLKEM_768);
    bool sel1024 = (ctx->selected_param == MLKEM_1024);

    if (GuiButton((Rectangle){ x, y, w, 24 },
                  sel512 ? "> ML-KEM-512" : "  ML-KEM-512")) {
        ctx->selected_param = MLKEM_512;
    }
    y += 28;
    if (GuiButton((Rectangle){ x, y, w, 24 },
                  sel768 ? "> ML-KEM-768" : "  ML-KEM-768")) {
        ctx->selected_param = MLKEM_768;
    }
    y += 28;
    if (GuiButton((Rectangle){ x, y, w, 24 },
                  sel1024 ? "> ML-KEM-1024" : "  ML-KEM-1024")) {
        ctx->selected_param = MLKEM_1024;
    }
    y += 40;

    /* Section: Compression */
    DrawAppText("Compression Level", x, y, FONT_SIZE, DIM_TEXT_COLOR);
    y += 20;

    float level = (float)ctx->compress_level;
    GuiSliderBar((Rectangle){ x, y, w, 20 }, "0", "9", &level, 0, 9);
    ctx->compress_level = (int)level;
    y += 30;

    char level_text[32];
    snprintf(level_text, sizeof(level_text), "Level: %d", ctx->compress_level);
    DrawAppText(level_text, x, y, FONT_SIZE, TEXT_COLOR);
    y += 30;

    /* Section: Key Selection */
    DrawAppText("Select Key", x, y, FONT_SIZE, DIM_TEXT_COLOR);
    y += 20;

    if (ctx->keystore.count == 0) {
        DrawAppText("No keys found.", x, y, FONT_SIZE, DIM_TEXT_COLOR);
        DrawAppText("Use Key Manager", x, y + 22, FONT_SIZE, DIM_TEXT_COLOR);
    } else {
        for (uint32_t i = 0; i < ctx->keystore.count && i < 10; i++) {
            bool is_selected = ((int)i == ctx->selected_key);

            /* Build label with type indicator */
            char label[160];
            snprintf(label, sizeof(label), "%s %s [%s]",
                     is_selected ? ">" : " ",
                     ctx->keystore.entries[i].label,
                     ctx->keystore.entries[i].has_secret ? "priv" : "pub");

            Color lbl_color = is_selected ? ACCENT_COLOR : TEXT_COLOR;

            /* Clickable row */
            Rectangle row = { (float)x, (float)y, (float)w, 18 };
            if (CheckCollisionPointRec(GetMousePosition(), row) &&
                IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                ctx->selected_key = (int)i;
            }

            DrawAppText(label, x + 4, y + 2, FONT_SIZE, lbl_color);
            y += 20;
        }
    }
}

/* ---------- File list (main area) ---------- */

static void draw_file_list(GuiContext *ctx)
{
    int lx = SIDEBAR_WIDTH + 1;
    int ly = TOOLBAR_HEIGHT + 1;
    int lw = GUI_WIDTH - SIDEBAR_WIDTH - 1;
    int lh = GUI_HEIGHT - TOOLBAR_HEIGHT - STATUSBAR_HEIGHT - 1;

    /* Header */
    DrawRectangle(lx, ly, lw, 24, PANEL_COLOR);
    DrawAppText("  File Name", lx + 8, ly + 5, FONT_SIZE, DIM_TEXT_COLOR);
    DrawAppText("Size", lx + lw - 200, ly + 5, FONT_SIZE, DIM_TEXT_COLOR);
    DrawAppText("Status", lx + lw - 100, ly + 5, FONT_SIZE, DIM_TEXT_COLOR);

    int fy = ly + 28;
    int row_h = 24;
    int visible_rows = (lh - 28) / row_h;
    int start = ctx->scroll_offset;

    /* If we have an opened+unlocked archive, show its entries */
    if (ctx->archive && ctx->archive->entries) {
        uint32_t end = (uint32_t)(start + visible_rows);
        if (end > ctx->archive->file_count) end = ctx->archive->file_count;

        /* Scroll indicator */
        if (ctx->archive->file_count > (uint32_t)visible_rows) {
            char scroll_info[32];
            snprintf(scroll_info, sizeof(scroll_info), "%d-%u of %u",
                     start + 1, end, ctx->archive->file_count);
            int siw = MeasureAppText(scroll_info, FONT_SIZE_SMALL);
            DrawAppText(scroll_info, lx + lw - siw - 8, ly + 5, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
        }

        for (uint32_t i = (uint32_t)start; i < end; i++) {
            KyberFileEntry *e = &ctx->archive->entries[i];
            Color rowbg = (i % 2 == 0) ? BG_COLOR : PANEL_COLOR;
            bool selected = ((int)i == ctx->selected_file);
            if (selected) rowbg = ACCENT_COLOR;

            DrawRectangle(lx, fy, lw, row_h, rowbg);
            DrawAppText(e->name, lx + 8, fy + 3, FONT_SIZE, TEXT_COLOR);

            char size_str[32];
            snprintf(size_str, sizeof(size_str), "%llu B",
                     (unsigned long long)e->original_size);
            DrawAppText(size_str, lx + lw - 200, fy + 3, FONT_SIZE, TEXT_COLOR);

            const char *comp = e->compression ? "deflate" : "store";
            DrawAppText(comp, lx + lw - 100, fy + 3, FONT_SIZE, DIM_TEXT_COLOR);

            Rectangle row = { (float)lx, (float)fy, (float)lw, (float)row_h };
            Vector2 mouse = GetMousePosition();
            if (CheckCollisionPointRec(mouse, row)) {
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    ctx->selected_file = (int)i;
                    ctx->show_ctx_menu = false;
                }
                if (IsMouseButtonPressed(MOUSE_BUTTON_RIGHT)) {
                    ctx->selected_file = (int)i;
                    ctx->ctx_menu_target = (int)i;
                    ctx->ctx_menu_x = (int)mouse.x;
                    ctx->ctx_menu_y = (int)mouse.y;
                    ctx->show_ctx_menu = true;
                }
            }

            fy += row_h;
        }
    }
    /* Opened but not yet unlocked archive */
    else if (ctx->archive) {
        char info[128];
        snprintf(info, sizeof(info), "Encrypted archive: %u files — click Decrypt to unlock",
                 ctx->archive->file_count);
        int tw = MeasureAppText(info, FONT_SIZE);
        DrawAppText(info, lx + (lw - tw) / 2, ly + lh / 2 - 8, FONT_SIZE, DIM_TEXT_COLOR);
    }
    /* Pending files for new archive */
    else if (ctx->pending_count > 0) {
        uint32_t end = (uint32_t)(start + visible_rows);
        if (end > ctx->pending_count) end = ctx->pending_count;

        if (ctx->pending_count > (uint32_t)visible_rows) {
            char scroll_info[32];
            snprintf(scroll_info, sizeof(scroll_info), "%d-%u of %u",
                     start + 1, end, ctx->pending_count);
            int siw = MeasureAppText(scroll_info, FONT_SIZE_SMALL);
            DrawAppText(scroll_info, lx + lw - siw - 8, ly + 5, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
        }

        for (uint32_t i = (uint32_t)start; i < end; i++) {
            Color rowbg = (i % 2 == 0) ? BG_COLOR : PANEL_COLOR;
            bool selected = ((int)i == ctx->selected_file);
            if (selected) rowbg = ACCENT_COLOR;

            DrawRectangle(lx, fy, lw, row_h, rowbg);

            const char *display = ctx->pending_files[i];
            const char *slash = strrchr(display, '/');
            const char *bslash = strrchr(display, '\\');
            if (bslash && (!slash || bslash > slash)) slash = bslash;
            if (slash) display = slash + 1;

            DrawAppText(display, lx + 8, fy + 3, FONT_SIZE, TEXT_COLOR);
            DrawAppText("pending", lx + lw - 100, fy + 3, FONT_SIZE, DIM_TEXT_COLOR);

            Rectangle row = { (float)lx, (float)fy, (float)lw, (float)row_h };
            Vector2 mouse = GetMousePosition();
            if (CheckCollisionPointRec(mouse, row)) {
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    ctx->selected_file = (int)i;
                    ctx->show_ctx_menu = false;
                }
                if (IsMouseButtonPressed(MOUSE_BUTTON_RIGHT)) {
                    ctx->selected_file = (int)i;
                    ctx->ctx_menu_target = (int)i;
                    ctx->ctx_menu_x = (int)mouse.x;
                    ctx->ctx_menu_y = (int)mouse.y;
                    ctx->show_ctx_menu = true;
                }
            }

            fy += row_h;
        }
    } else {
        const char *hint = "Drag and drop files here, or use Add Files / Open Archive";
        int tw = MeasureAppText(hint, FONT_SIZE);
        DrawAppText(hint, lx + (lw - tw) / 2, ly + lh / 2 - 8, FONT_SIZE, DIM_TEXT_COLOR);
    }
}

/* ---------- Status bar ---------- */

static void draw_statusbar(GuiContext *ctx)
{
    int sy = GUI_HEIGHT - STATUSBAR_HEIGHT;

    DrawRectangle(0, sy, GUI_WIDTH, STATUSBAR_HEIGHT, PANEL_COLOR);
    DrawLine(0, sy, GUI_WIDTH, sy, BORDER_COLOR);
    DrawAppText(ctx->status_text, PADDING, sy + 9, FONT_SIZE_SMALL, TEXT_COLOR);

    /* Show param set on right */
    const char *param_str = ctx->selected_param == MLKEM_512 ? "ML-KEM-512" :
                            ctx->selected_param == MLKEM_768 ? "ML-KEM-768" :
                            "ML-KEM-1024";

    /* Show selected key name next to param */
    char right_text[256];
    if (ctx->selected_key >= 0 && (uint32_t)ctx->selected_key < ctx->keystore.count) {
        snprintf(right_text, sizeof(right_text), "%s | Key: %s",
                 param_str, ctx->keystore.entries[ctx->selected_key].label);
    } else {
        snprintf(right_text, sizeof(right_text), "%s | No key selected", param_str);
    }

    int tw = MeasureAppText(right_text, FONT_SIZE_SMALL);
    DrawAppText(right_text, GUI_WIDTH - tw - PADDING, sy + 9, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
}

/* ---------- Key Manager dialog ---------- */

static void draw_key_manager(GuiContext *ctx)
{
    int dw = 540, dh = 440;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);
    DrawRectangleLines(dx, dy, dw, dh, ACCENT_COLOR);

    DrawAppText("Key Manager", dx + PADDING, dy + PADDING, FONT_SIZE, TEXT_COLOR);

    if (GuiButton((Rectangle){ dx + dw - 30, dy + 5, 24, 24 }, "X")) {
        ctx->show_keymgr = false;
    }

    int y = dy + 40;

    /* Label input */
    DrawAppText("Label:", dx + PADDING, y + 6, FONT_SIZE, DIM_TEXT_COLOR);
    if (GuiTextBox((Rectangle){ dx + 55, y, 150, BTN_HEIGHT },
                   ctx->keygen_label, sizeof(ctx->keygen_label),
                   ctx->keygen_label_edit)) {
        ctx->keygen_label_edit = !ctx->keygen_label_edit;
    }

    if (GuiButton((Rectangle){ dx + 215, y, 140, BTN_HEIGHT }, "Generate Keypair")) {
        const char *label = ctx->keygen_label[0] ? ctx->keygen_label : "default";

        KyberError err = keystore_generate(&ctx->keystore, label,
                                           ctx->selected_param);
        if (err == KYBER_OK) {
            keystore_save(&ctx->keystore);
            ctx->selected_key = (int)ctx->keystore.count - 1;
            char msg[192];
            snprintf(msg, sizeof(msg), "Keypair '%s' generated.", label);
            gui_show_message(ctx, msg, false);
        } else {
            gui_show_message(ctx, kyber_error_str(err), true);
        }
    }

    y += BTN_HEIGHT + PADDING;

    if (GuiButton((Rectangle){ dx + PADDING, y, 120, BTN_HEIGHT }, "Import Public")) {
        const char *filters[] = { "*.pub", "*.key", "*.*" };
        const char *path = tinyfd_openFileDialog(
            "Import Public Key", "", 3, filters, "Key Files", 0);
        if (path) {
            char label[64];
            /* Use filename as label */
            const char *fname = strrchr(path, '/');
            const char *bslash = strrchr(path, '\\');
            if (bslash && (!fname || bslash > fname)) fname = bslash;
            fname = fname ? fname + 1 : path;
            snprintf(label, sizeof(label), "%.*s", 60, fname);

            KyberError err = keystore_import_public(&ctx->keystore, label, path);
            if (err == KYBER_OK) {
                keystore_save(&ctx->keystore);
                gui_show_message(ctx, "Public key imported.", false);
            } else {
                gui_show_message(ctx, kyber_error_str(err), true);
            }
        }
    }

    if (GuiButton((Rectangle){ dx + PADDING + 130, y, 120, BTN_HEIGHT }, "Export Public")) {
        if (ctx->selected_key >= 0 && (uint32_t)ctx->selected_key < ctx->keystore.count) {
            const char *filters[] = { "*.pub" };
            const char *path = tinyfd_saveFileDialog(
                "Export Public Key", "key.pub", 1, filters, "Public Key (*.pub)");
            if (path) {
                KyberError err = keystore_export_public(
                    &ctx->keystore, (uint32_t)ctx->selected_key, path);
                if (err == KYBER_OK) {
                    gui_show_message(ctx, "Public key exported.", false);
                } else {
                    gui_show_message(ctx, kyber_error_str(err), true);
                }
            }
        } else {
            gui_show_message(ctx, "No key selected.", true);
        }
    }

    y += BTN_HEIGHT + PADDING;

    /* Second row: keypair import/export */
    if (GuiButton((Rectangle){ dx + PADDING, y, 140, BTN_HEIGHT }, "Import Keypair")) {
        const char *filters[] = { "*.kyp", "*.pub", "*.*" };
        const char *path = tinyfd_openFileDialog(
            "Import Keypair", "", 3, filters, "Key Files", 0);
        if (path) {
            char label[64];
            const char *fname = strrchr(path, '/');
            const char *bslash = strrchr(path, '\\');
            if (bslash && (!fname || bslash > fname)) fname = bslash;
            fname = fname ? fname + 1 : path;
            snprintf(label, sizeof(label), "%.*s", 60, fname);

            KyberError err = keystore_import_keypair(&ctx->keystore, label, path);
            if (err == KYBER_OK) {
                keystore_save(&ctx->keystore);
                ctx->selected_key = (int)ctx->keystore.count - 1;
                gui_show_message(ctx, "Keypair imported.", false);
            } else {
                gui_show_message(ctx, kyber_error_str(err), true);
            }
        }
    }

    if (GuiButton((Rectangle){ dx + 160, y, 140, BTN_HEIGHT }, "Export Keypair")) {
        if (ctx->selected_key >= 0 && (uint32_t)ctx->selected_key < ctx->keystore.count) {
            KeystoreEntry *sel = &ctx->keystore.entries[ctx->selected_key];
            if (!sel->has_secret) {
                gui_show_message(ctx, "Selected key has no private key to export.", true);
            } else {
                const char *filters[] = { "*.kyp" };
                const char *path = tinyfd_saveFileDialog(
                    "Export Keypair", "key.kyp", 1, filters, "Keypair (*.kyp)");
                if (path) {
                    KyberError err = keystore_export_keypair(
                        &ctx->keystore, (uint32_t)ctx->selected_key, path);
                    if (err == KYBER_OK) {
                        gui_show_message(ctx, "Keypair exported.", false);
                    } else {
                        gui_show_message(ctx, kyber_error_str(err), true);
                    }
                }
            }
        } else {
            gui_show_message(ctx, "No key selected.", true);
        }
    }

    y += BTN_HEIGHT + PADDING;

    /* Fingerprint of the selected key — read this aloud to the other party to
     * confirm the key is authentic, then click "Mark Verified". */
    if (ctx->selected_key >= 0 && (uint32_t)ctx->selected_key < ctx->keystore.count) {
        KeystoreEntry *sk = &ctx->keystore.entries[ctx->selected_key];
        char fp[KYBER_FINGERPRINT_LEN];
        kyber_fingerprint(sk->public_key, sk->public_key_len, fp, sizeof(fp));
        bool verified = keystore_is_verified(&ctx->keystore, (uint32_t)ctx->selected_key);

        char fline[200];
        snprintf(fline, sizeof(fline), "Fingerprint (%s): %s", sk->label, fp);
        DrawAppText(fline, dx + PADDING, y, FONT_SIZE_SMALL, ACCENT_COLOR);

        if (verified) {
            DrawAppText("verified", dx + dw - 90, y, FONT_SIZE_SMALL, SUCCESS_COLOR);
        } else if (GuiButton((Rectangle){ dx + dw - 130, y - 4, 120, 22 }, "Mark Verified")) {
            keystore_mark_verified(&ctx->keystore, (uint32_t)ctx->selected_key);
            gui_show_message(ctx, "Key marked as verified.", false);
        }
    } else {
        DrawAppText("Select a key to see its fingerprint.",
                    dx + PADDING, y, FONT_SIZE_SMALL, DIM_TEXT_COLOR);
    }
    y += 24;

    /* Key list header */
    DrawAppText("Label", dx + PADDING, y, FONT_SIZE, DIM_TEXT_COLOR);
    DrawAppText("Algorithm", dx + 200, y, FONT_SIZE, DIM_TEXT_COLOR);
    DrawAppText("Type", dx + 340, y, FONT_SIZE, DIM_TEXT_COLOR);
    y += 18;

    for (uint32_t i = 0; i < ctx->keystore.count; i++) {
        KeystoreEntry *e = &ctx->keystore.entries[i];

        bool is_selected = ((int)i == ctx->selected_key);
        Color row_color = is_selected ? ACCENT_COLOR : TEXT_COLOR;

        /* Click to select */
        Rectangle row = { (float)(dx + PADDING), (float)(y - 2),
                          (float)(dw - 80), 18 };
        if (CheckCollisionPointRec(GetMousePosition(), row) &&
            IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            ctx->selected_key = (int)i;
        }

        DrawAppText(e->label, dx + PADDING, y, FONT_SIZE, row_color);

        const char *alg = e->param == MLKEM_512 ? "ML-KEM-512" :
                          e->param == MLKEM_768 ? "ML-KEM-768" : "ML-KEM-1024";
        DrawAppText(alg, dx + 200, y, FONT_SIZE, row_color);
        DrawAppText(e->has_secret ? "keypair" : "public", dx + 340, y, FONT_SIZE, row_color);

        if (GuiButton((Rectangle){ dx + dw - 70, y - 2, 50, 18 }, "Delete")) {
            keystore_remove(&ctx->keystore, i);
            keystore_save(&ctx->keystore);
            if (ctx->selected_key >= (int)ctx->keystore.count) {
                ctx->selected_key = (int)ctx->keystore.count - 1;
            }
            break;
        }

        y += 22;
        if (y > dy + dh - 20) break;
    }

    if (ctx->keystore.count == 0) {
        DrawAppText("No keys in keystore.", dx + PADDING, y, FONT_SIZE, DIM_TEXT_COLOR);
    }
}

/* ---------- Progress overlay ---------- */

static void draw_progress_overlay(GuiContext *ctx)
{
    /* Transfers get extra height for a Cancel button; encrypt does not. */
    bool cancelable = ctx->transfer_active;
    int dw = 420;
    int dh = cancelable ? 150 : 110;
    int dx = (GUI_WIDTH - dw) / 2;
    int dy = (GUI_HEIGHT - dh) / 2;

    DrawRectangle(0, 0, GUI_WIDTH, GUI_HEIGHT, (Color){0, 0, 0, 120});
    DrawRectangle(dx, dy, dw, dh, PANEL_COLOR);
    DrawRectangleLines(dx, dy, dw, dh, ACCENT_COLOR);

    DrawAppText(ctx->status_text, dx + PADDING, dy + PADDING, FONT_SIZE, TEXT_COLOR);

    /* Clamp the fill so a -1 (unknown size) or overshoot can't draw oddly. */
    float frac = ctx->progress;
    if (frac < 0.0f) frac = 0.0f;
    if (frac > 1.0f) frac = 1.0f;

    int bar_h = 24;
    int bar_y = dy + 48;
    int bar_x = dx + PADDING;
    int bar_w = dw - 2 * PADDING;

    DrawRectangle(bar_x, bar_y, bar_w, bar_h, BG_COLOR);
    DrawRectangle(bar_x, bar_y, (int)(bar_w * frac), bar_h, ACCENT_COLOR);
    DrawRectangleLines(bar_x, bar_y, bar_w, bar_h, BORDER_COLOR);

    char pct[16];
    snprintf(pct, sizeof(pct), "%.0f%%", frac * 100.0f);
    int tw = MeasureAppText(pct, FONT_SIZE_SMALL);
    DrawAppText(pct, bar_x + (bar_w - tw) / 2, bar_y + (bar_h - FONT_SIZE_SMALL) / 2,
                FONT_SIZE_SMALL, TEXT_COLOR);

    if (cancelable) {
        Rectangle btn = { (float)(dx + dw - 110 - PADDING),
                          (float)(dy + dh - BTN_HEIGHT - PADDING),
                          110, (float)BTN_HEIGHT };
        bool already = ctx->transfer_cancel != 0;
        if (already) GuiSetState(STATE_DISABLED);
        if (GuiButton(btn, already ? "Canceling..." : "Cancel")) {
            ctx->transfer_cancel = 1;
        }
        if (already) GuiSetState(STATE_NORMAL);
    }
}

/* ---------- Main GUI entry ---------- */

int gui_run(void)
{
    SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_MSAA_4X_HINT);
    InitWindow(GUI_WIDTH, GUI_HEIGHT, GUI_TITLE);
    SetTargetFPS(60);

    /* Load a clean TTF font from the system. Prefer Segoe UI Semibold — the
     * heavier weight stays crisp and legible on the dark background, where the
     * thinner regular/semilight weights wash out. The atlas is baked at
     * FONT_LOAD_SIZE (3x) and filtered bilinearly so scaled-down text is sharp
     * rather than blurry. */
    const char *font_paths[] = {
        "C:\\Windows\\Fonts\\seguisb.ttf",   /* Segoe UI Semibold  */
        "C:\\Windows\\Fonts\\segoeuib.ttf",  /* Segoe UI Bold      */
        "C:\\Windows\\Fonts\\segoeui.ttf",   /* Segoe UI Regular   */
        "C:\\Windows\\Fonts\\arialbd.ttf",   /* Arial Bold         */
    };
    for (int i = 0; i < 4; i++) {
        g_font = LoadFontEx(font_paths[i], FONT_LOAD_SIZE, NULL, 512);
        if (g_font.texture.id > 0) {
            SetTextureFilter(g_font.texture, TEXTURE_FILTER_BILINEAR);
            break;
        }
    }
    if (g_font.texture.id > 0) {
        GuiSetFont(g_font);
    }

    /* Cohesive dark theme for raygui controls so buttons/inputs match the
     * hand-drawn panels instead of the default light-grey look. */
    GuiSetStyle(DEFAULT, TEXT_SIZE, FONT_SIZE);
    GuiSetStyle(DEFAULT, TEXT_SPACING, 1);
    GuiSetStyle(DEFAULT, BACKGROUND_COLOR,      ColorToInt(BG_COLOR));
    GuiSetStyle(DEFAULT, LINE_COLOR,            ColorToInt(BORDER_COLOR));

    GuiSetStyle(DEFAULT, BASE_COLOR_NORMAL,     ColorToInt(PANEL_HI_COLOR));
    GuiSetStyle(DEFAULT, BORDER_COLOR_NORMAL,   ColorToInt(BORDER_COLOR));
    GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL,     ColorToInt(TEXT_COLOR));

    GuiSetStyle(DEFAULT, BASE_COLOR_FOCUSED,    ColorToInt(((Color){ 56, 62, 74, 255 })));
    GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED,  ColorToInt(ACCENT_COLOR));
    GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED,    ColorToInt(TEXT_COLOR));

    GuiSetStyle(DEFAULT, BASE_COLOR_PRESSED,    ColorToInt(ACCENT_COLOR));
    GuiSetStyle(DEFAULT, BORDER_COLOR_PRESSED,  ColorToInt(ACCENT_COLOR));
    GuiSetStyle(DEFAULT, TEXT_COLOR_PRESSED,    ColorToInt(WHITE));

    transfer_global_init();

    GuiContext ctx;
    gui_init(&ctx);

    while (!WindowShouldClose()) {
        gui_update(&ctx);

        BeginDrawing();
        gui_draw(&ctx);
        EndDrawing();
    }

    gui_shutdown(&ctx);
    transfer_global_cleanup();
    UnloadFont(g_font);
    CloseWindow();
    return 0;
}
