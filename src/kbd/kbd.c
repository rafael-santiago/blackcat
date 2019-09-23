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
#if !defined(_WIN32)
# include <termios.h>
#else
# include <windows.h>
#endif
#include <signal.h>
#include <unistd.h>

#if !defined(_WIN32)
static struct termios old, new;
#else
static DWORD con_mode;
#endif

static void getuserkey_sigint_watchdog(int signo);

#if defined(_WIN32)

#define stty_echo_off system("stty -echo");

#define stty_echo_on system("stty echo");

static int is_toynix(void);
#endif

static void getuserkey_sigint_watchdog(int signo) {
#if !defined(_WIN32)
    tcsetattr(STDOUT_FILENO, TCSAFLUSH, &old);
#else
    if (!is_toynix()) {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), con_mode);
    } else {
        stty_echo_on
    }
#endif
    exit(1);
}

#if !defined(_WIN32)

kryptos_u8_t *blackcat_getuserkey(size_t *key_size) {
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

    if (size == 0) {
        goto blackcat_getuserkey_epilogue;
    }

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

#else

static int is_toynix(void) {
    static int is = -1;
    char data[256];
    if (is == -1) {
        is = (getenv("MSYSTEM") != NULL);
    }
    return is;
}

kryptos_u8_t *blackcat_getuserkey(size_t *key_size) {
    kryptos_u8_t *key = NULL, *kp;
    char line[65535], *lp, *lp_end;
    size_t size;

    if (!is_toynix()) {
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &con_mode);
    }

    if (key_size == NULL) {
        return NULL;
    }

    *key_size = 0;

    if (!is_toynix()) {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), con_mode & (~ENABLE_ECHO_INPUT));
    } else {
        stty_echo_off
    }

    signal(SIGINT, getuserkey_sigint_watchdog);
    signal(SIGTERM, getuserkey_sigint_watchdog);

    fgets(line, sizeof(line), stdin);
    //fprintf(stdout, "\n");

    size = strlen(line) - 1;

    if (size == 0) {
        goto blackcat_getuserkey_epilogue;
    }

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

    if (!is_toynix()) {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), con_mode);
    } else {
        stty_echo_on
    }

    return key;
}

#undef stty_echo_on

#undef stty_echo_off

#endif
