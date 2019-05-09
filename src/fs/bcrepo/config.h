/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_FS_BCREPO_CONFIG_H
#define BLACKCAT_FS_BCREPO_CONFIG_H 1

struct bcrepo_config_ctx {
    struct bcrepo_config_priv_ctx *priv;
    char *line, *line_end;
    char *word, *word_end;
};

struct bcrepo_config_ctx *bcrepo_ld_config(void);

int bcrepo_config_get_section(struct bcrepo_config_ctx *cfg, const char *section);

void bcrepo_release_config(struct bcrepo_config_ctx *cfg);

int bcrepo_config_get_next_line(struct bcrepo_config_ctx *cfg);

int bcrepo_config_get_next_word(struct bcrepo_config_ctx *cfg);

#endif
