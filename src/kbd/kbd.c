/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <kbd/kbd.h>
#include <ctype.h>
#include <stdio.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>

static struct termios old, new;

static void getuserkey_sigint_watchdog(int signo);

static void getuserkey_sigint_watchdog(int signo) {
    tcsetattr(STDOUT_FILENO, TCSAFLUSH, &old);
    exit(1);
}

kryptos_u8_t *blackcat_getuserkey(size_t *key_size) {
    // WARN(Rafael): This function is actually being tested with cmd tool tests.
    kryptos_u8_t *key = NULL, *kp;
    char line[65535], *lp, *lp_end;
    size_t size;

    if (key_size == NULL || tcgetattr(STDOUT_FILENO, &old) != 0) {
        return NULL;
    }

    *key_size = 0;

    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &new) != 0) {
        goto blackcat_getuserkey_epilogue;
    }

    signal(SIGINT, getuserkey_sigint_watchdog);
    signal(SIGTERM, getuserkey_sigint_watchdog);

    fgets(line, sizeof(line), stdin);
    //fprintf(stdout, "\n");

    size = strlen(line) - 1;

    key = (kryptos_u8_t *) kryptos_newseg(size);
    kp = key;
    lp = &line[0];
    lp_end = lp + size;

    while (lp < lp_end) {
        if (*lp == '\\') {
            lp += 1;
            switch (*lp) {
                case 'x':
                    if ((lp + 2) < lp_end && isxdigit(lp[1]) && isxdigit(lp[2])) {
#define getnibble(b) ( isdigit((b)) ? ( (b) - '0' ) : ( toupper((b)) - 55 ) )
                        *kp = getnibble(lp[1]) << 4 | getnibble(lp[2]);
#undef getnibble
                        lp += 2;
                    } else {
                        *kp = *lp;
                    }
                    break;

                case 'n':
                    *kp = '\n';
                    break;

                case 't':
                    *kp = '\t';
                    break;

                default:
                    *kp = *lp;
                    break;
            }
        } else {
            *kp = *lp;
        }

        lp++;
        kp++;
    }

    *key_size = kp - key;

blackcat_getuserkey_epilogue:

    memset(line, 0, sizeof(line));

    tcsetattr(STDOUT_FILENO, TCSAFLUSH, &old);

    return key;
}
