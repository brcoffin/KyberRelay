#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "kyber_common.h"
#include "crypto.h"

#ifdef KYBER_CLI_MODE
#include "cli.h"
#endif

#ifdef KYBER_GUI_MODE
#include "gui.h"
#endif

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Fatal: failed to initialize libsodium.\n");
        return 1;
    }

    if (!kyber_aes256gcm_available()) {
        fprintf(stderr,
            "Fatal: AES-256-GCM is not available on this CPU.\n"
            "Kyber-Zip requires hardware AES-NI support.\n");
        return 1;
    }

#if defined(KYBER_GUI_MODE) && defined(KYBER_CLI_MODE)
    if (argc > 1 && strcmp(argv[1], "--gui") != 0) {
        return cli_run(argc, argv);
    }
    return gui_run();

#elif defined(KYBER_CLI_MODE)
    return cli_run(argc, argv);

#elif defined(KYBER_GUI_MODE)
    (void)argc; (void)argv;
    return gui_run();

#else
    #error "Define KYBER_CLI_MODE or KYBER_GUI_MODE"
#endif
}
