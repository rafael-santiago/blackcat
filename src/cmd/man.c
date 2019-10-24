/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/man.h>
#include <kryptos_memory.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static FILE *get_stdout(void);

int blackcat_cmd_man(void) {
    int exit_code = ENOENT;
    FILE *output = get_stdout(), *fp = NULL;
    unsigned char *data = NULL;
    size_t data_size;


    if (output != NULL) {
#if defined(__unix__)
        fp = fopen("/usr/local/share/blackcat/doc/MANUAL.txt", "r");
#elif defined(_WIN32)
        fp = fopen("C:\\blackcat\\doc\\MANUAL.txt", "r");
#else
# error Some code wanted.
#endif

        if (fp == NULL) {
            fprintf(stderr, "ERROR: Unable to find the manual.\n");
            goto blackcat_cmd_man_epilogue;
        }

        fseek(fp, 0L, SEEK_END);
        data_size = (size_t) ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        data = (unsigned char *) kryptos_newseg(data_size + 1);
        memset(data, 0, data_size + 1);
        fread(data, 1, data_size, fp);
        fprintf(output, "%s", data);
        kryptos_freeseg(data, data_size);
        data = NULL;
        fclose(fp);
        fp = NULL;
    }

    exit_code = 0;

blackcat_cmd_man_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (output != NULL && output != &stdout[0]) {
        pclose(output);
    }

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    return exit_code;
}

int blackcat_cmd_man_help(void) {
    fprintf(stdout, "use: blackcat man\n");
    return 0;
}

static FILE *get_stdout(void) {
#if defined(__unix__)
    FILE *out;
    char *pager = "less";
    if (system("less --version 2>/dev/null") != 0) {
        if (system("more -V 2>/dev/null") == 0) {
            pager = "more";
        } else {
            out = stdout;
            goto get_stdout_epilogue;
        }
    }

    if ((out = popen(pager, "w")) == NULL) {
        out = stdout;
    }

get_stdout_epilogue:

#elif defined(_WIN32)
    if ((out = popen("more", "w")) == NULL) {
        out = stdout;
    }
#else
# error Some code wanted.
#endif
    return out;
}
