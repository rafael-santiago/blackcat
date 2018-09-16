/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/lkm.h>
#include <cmd/options.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#if defined(__linux__)
# include <sys/syscall.h>
#elif defined(__FreeBSD__)
# include <sys/param.h>
# include <sys/linker.h>
#elif defined(__NetBSD__)
# include <sys/module.h>
# include <prop/proplib.h>
# include <string.h>
#endif

#define BLACKCAT_LKM_PATH_ENV "BLACKCAT_LKM_PATH"

static int do_load(void);

int blackcat_cmd_lkm(void) {
    if (blackcat_get_bool_option("load", 0) == 1) {
        return do_load();
    }

    fprintf(stderr, "ERROR: Wtf you are intending to do?\n");

    return 1;
}

int blackcat_cmd_lkm_help(void) {
    fprintf(stdout, "use: blackcat lkm --load [<path>]\n");
}

static int do_load(void) {
    int err = 1;
#if defined(__linux__)
    int fd;
    char *modpath;

    if ((modpath = blackcat_get_argv(0)) == NULL) {
        modpath = getenv(BLACKCAT_LKM_PATH_ENV);
    }

    if (modpath == NULL) {
        fprintf(stderr, "ERROR: Unable to find blackcat's LKM.\n");
        goto do_load_epilogue;
    }

    if ((fd = open(modpath, O_RDONLY)) == -1) {
        fprintf(stderr, "ERROR: Unable to read the blackcat's LKM.\n");
        goto do_load_epilogue;
    }

#define init_lnx_lkm(fd) syscall(__NR_finit_module, fd, "", 0)

    if ((err = init_lnx_lkm(fd)) != 0) {
        fprintf(stderr, "ERROR: Unable to load the blackcat's LKM.\n");
    }

#undef init_lnx_lkm

    close(fd);
#elif defined(__FreeBSD__)
    char *modpath;

    if ((modpath = blackcat_get_argv(0)) == NULL) {
        modpath = getenv(BLACKCAT_LKM_PATH_ENV);
    }

    if (modpath == NULL) {
        fprintf(stderr, "ERROR: Unable to find blackcat's LKM.\n");
        goto do_load_epilogue;
    }

    if ((err = kldload(modpath)) != 0) {
        fprintf(stderr, "ERROR: Unable to load the blackcat's LKM.\n");
    }
#elif defined(__NetBSD__)
   char *modpath, *props_str;
   modctl_load_t mcl;
   prop_dictionary_t props;

   if ((modpath = blackcat_get_argv(0)) == NULL) {
        modpath = getenv(BLACKCAT_LKM_PATH_ENV);
   }

   if (modpath == NULL) {
        fprintf(stderr, "ERROR: Unable to find blackcat`s LKM.\n");
        goto do_load_epilogue;
   }

   props = prop_dictionary_create();
   props_str = prop_dictionary_externalize(props);
   prop_object_release(props);

   if (props_str == NULL) {
        fprintf(stderr, "ERROR: NULL prop str.\n");
        goto do_load_epilogue;
   }

   mcl.ml_filename = modpath;
   mcl.ml_flags = 0;
   mcl.ml_props = props_str;
   mcl.ml_propslen = strlen(props_str);

   if ((err = modctl(MODCTL_LOAD, &mcl)) != 0) {
        fprintf(stderr, "ERROR: Unable to load the blackcat`s LKM.\n");
   }

   free(props_str);
#else
    fprintf(stderr, "ERROR: No support for this platform.\n");
#endif

do_load_epilogue:

    return err;
}

#undef BLACKCAT_LKM_PATH_ENV
