/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_DID_YOU_MEAN_H
#define BLACKCAT_CMD_DID_YOU_MEAN_H 1

#include <stdlib.h>

int did_you_mean(const char *user_command, const int max_distance);

int custom_did_you_mean(const char *data, const int max_distance, const char **known_terms, const size_t known_terms_nr);

#endif
