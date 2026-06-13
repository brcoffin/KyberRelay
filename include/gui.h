#ifndef KYBER_GUI_H
#define KYBER_GUI_H

#include "kyber_common.h"
#include "archive.h"
#include "keystore.h"

/* GUI window dimensions */
#define GUI_WIDTH   1000
#define GUI_HEIGHT  640
#define GUI_TITLE   "Kyber-Zip"

/* GUI application state */
typedef enum {
    GUI_VIEW_MAIN,        /* main archive view */
    GUI_VIEW_KEY_MANAGER, /* key management dialog */
    GUI_VIEW_SETTINGS,    /* settings panel */
    GUI_VIEW_PROGRESS,    /* progress during pack/unpack */
} GuiView;

/* GUI context */
typedef struct {
    GuiView         current_view;
    KyberArchive   *archive;        /* currently open archive (or NULL) */
    Keystore        keystore;
    KyberParamSet   selected_param; /* current parameter set selection */
    int             compress_level; /* current compression level */
    bool            show_keymgr;    /* key manager dialog open */
    bool            show_settings;  /* settings panel open */

    /* Progress tracking */
    float           progress;       /* 0.0 - 1.0 */
    char            status_text[256];
    bool            operation_active;

    /* File list for new archive */
    char          **pending_files;
    uint32_t        pending_count;
    uint32_t        pending_capacity;

    /* Selected item in file list */
    int             selected_file;

    /* Selected key index in sidebar (-1 = none) */
    int             selected_key;

    /* Error/success message dialog */
    bool            show_message;
    char            message_text[256];
    bool            message_is_error;

    /* File list scroll */
    int             scroll_offset;  /* number of rows scrolled */

    /* Key label text input */
    char            keygen_label[128];
    bool            keygen_label_edit; /* true when textbox is active */

    /* Context menu */
    bool            show_ctx_menu;
    int             ctx_menu_x;
    int             ctx_menu_y;
    int             ctx_menu_target; /* index of right-clicked item */

    /* Async encrypt operation state */
    bool            encrypt_active;     /* true while encrypting across frames */
    KyberArchive   *encrypt_arc;       /* archive being built */
    char            encrypt_outpath[1024]; /* output path */
    uint32_t        encrypt_index;     /* next file to process */
    bool            encrypt_writing;   /* true when files done, writing archive */

    /* Secure transfer (relay) */
    char            relay_url[512];          /* base URL of the relay server */
    char            current_archive_path[1024]; /* on-disk path of the open/created .kyz, "" if none */

    /* Unverified-recipient warning before encrypting */
    bool            show_encrypt_confirm;    /* warning dialog open */
    bool            encrypt_confirmed;       /* user chose to proceed anyway */

    /* Unverified-recipient warning before sending (upload) */
    bool            show_send_confirm;       /* warning dialog open */

    /* Receive dialog */
    bool            show_receive;            /* receive dialog open */
    char            recv_code[64];           /* claim code being entered */
    bool            recv_code_edit;          /* code textbox active */
    bool            relay_url_edit;          /* relay-url textbox active */

    /* Background transfer worker (runs on its own thread so the UI stays live) */
    bool            transfer_active;         /* a transfer is in flight */
    int             transfer_kind;           /* 0 = upload, 1 = download */
    volatile double transfer_progress;       /* 0.0 - 1.0, written by worker */
    volatile int    transfer_done;           /* set by worker when finished */
    volatile int    transfer_status;         /* TransferStatus result */
    volatile int    transfer_cancel;         /* main thread sets to request abort */
    void           *transfer_thread;         /* worker thread HANDLE */
    char            transfer_code[64];        /* upload result / download input code */
    char            transfer_path[1024];      /* local file path for the transfer */
} GuiContext;

/* Launch the GUI application */
int gui_run(void);

/* GUI lifecycle */
void gui_init(GuiContext *ctx);
void gui_update(GuiContext *ctx);
void gui_draw(GuiContext *ctx);
void gui_shutdown(GuiContext *ctx);

#endif /* KYBER_GUI_H */
