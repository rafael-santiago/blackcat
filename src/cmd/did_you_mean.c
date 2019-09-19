/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <cmd/did_you_mean.h>
#include <cmd/levenshtein_distance.h>
#include <cmd/options.h>
#include <cmd/exec.h>
#include <stdio.h>

int did_you_mean(const char *user_command, const int max_distance) {
    int distances[0xFF];
    size_t d;
    int has_some_suggestion = 0, s_nr;

    for (d = 0; d < sizeof(distances) / sizeof(distances[0]); d++) {
        distances[d] = -1;
    }

    for (d = 0; d < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); d++) {
        distances[d] = levenshtein_distance(user_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, d));
        has_some_suggestion |= (distances[d] >= 1 && distances[d] <= max_distance);
    }

    if (has_some_suggestion) {
        s_nr = 0;
        fprintf(stderr, "Did you mean ");
        for (d = 0; d < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); d++) {
            if (distances[d] >= 1 && distances[d] <= max_distance) {
                if (s_nr > 0) {
                    fprintf(stderr, "%s ", ((d + 1) == GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)) ? " or" : ",");
                }
                fprintf(stderr, "'%s'", GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, d));
                s_nr++;
            }
        }
        fprintf(stderr, "?\n");
    }

    return has_some_suggestion;
}
