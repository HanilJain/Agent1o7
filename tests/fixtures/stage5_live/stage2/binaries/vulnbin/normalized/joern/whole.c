#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* vuln_path: argv[1] flows unchecked into a shell command via strcpy then
 * system() -- a real, CPG-verifiable command injection. Used as the
 * fixture's CONFIRMED case. */
int vuln_path(int argc, char *argv[]) {
    char buf[256];
    char cmd[512];

    if (argc < 2) {
        return 1;
    }

    strcpy(buf, argv[1]);
    snprintf(cmd, sizeof(cmd), "echo %s", buf);
    system(cmd);
    return 0;
}

/* safe_path: same shape, but the input is length-checked with strncpy and
 * the command itself is a fixed constant -- no attacker-controlled data
 * ever reaches system(). Used as the fixture's REFUTED case. */
int safe_path(int argc, char *argv[]) {
    char buf[256];

    if (argc < 2) {
        return 1;
    }

    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], sizeof(buf) - 1);
    system("echo fixed-safe-command");
    return 0;
}

int main(int argc, char *argv[]) {
    vuln_path(argc, argv);
    safe_path(argc, argv);
    return 0;
}
