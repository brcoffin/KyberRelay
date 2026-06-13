#ifndef KYBER_CLI_H
#define KYBER_CLI_H

/* Run the CLI with command-line arguments */
int cli_run(int argc, char **argv);

/* CLI subcommands */
int cli_keygen(int argc, char **argv);
int cli_pack(int argc, char **argv);
int cli_unpack(int argc, char **argv);
int cli_list(int argc, char **argv);
int cli_watch(int argc, char **argv);
int cli_keys(int argc, char **argv);
int cli_recv(int argc, char **argv);
int cli_recv_watch(int argc, char **argv);
int cli_verify(int argc, char **argv);

/* Print usage information */
void cli_usage(const char *progname);

#endif /* KYBER_CLI_H */
