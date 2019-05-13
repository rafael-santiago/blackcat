/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/bcrepo/config.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

struct bcrepo_config_priv_ctx {
    char *head, *tail;
    char *sec, *sec_end;
};

struct bcrepo_config_ctx *bcrepo_ld_config(void) {
    char *rootpath = bcrepo_get_rootpath();
    struct bcrepo_config_ctx *cfg = NULL;
    char cfgpath[4096];
    FILE *fp = NULL;
    size_t sz;

    if (rootpath  != NULL) {
        sprintf(cfgpath, "%s/" BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, rootpath);
        kryptos_freeseg(rootpath, strlen(rootpath));
        rootpath = NULL;

        if ((fp = fopen(cfgpath, "r")) == NULL) {
            goto bcrepo_ld_config_epilogue;
        }

        if ((cfg = (struct bcrepo_config_ctx *)kryptos_newseg(sizeof(struct bcrepo_config_ctx))) == NULL) {
            goto bcrepo_ld_config_epilogue;
        }

        if ((cfg->priv = (struct bcrepo_config_priv_ctx *)kryptos_newseg(sizeof(struct bcrepo_config_priv_ctx))) == NULL) {
            kryptos_freeseg(cfg, sizeof(struct bcrepo_config_ctx));
            cfg = NULL;
            goto bcrepo_ld_config_epilogue;
        }

        fseek(fp, 0L, SEEK_END);
        sz = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        if ((cfg->priv->head = (char *)kryptos_newseg(sz + 1)) == NULL) {
            kryptos_freeseg(cfg, sizeof(struct bcrepo_config_ctx));
            cfg = NULL;
            goto bcrepo_ld_config_epilogue;
        }

        memset(cfg->priv->head, 0, sz + 1);
        fread(cfg->priv->head, 1, sz, fp);
        fclose(fp);
        fp = NULL;

        cfg->priv->tail = cfg->priv->head + sz;
        cfg->priv->sec = cfg->line = cfg->word =
        cfg->priv->sec_end = cfg->line_end = cfg->word_end = NULL;
    }

bcrepo_ld_config_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    return cfg;
}

int bcrepo_config_get_section(struct bcrepo_config_ctx *cfg, const char *section) {
    int end;
    char temp[4096];

    if (cfg == NULL || cfg->priv->head == NULL || section == NULL) {
        return 0;
    }

    sprintf(temp, "%s:", section);

    cfg->priv->sec_end = cfg->line = cfg->line_end = cfg->word = cfg->word_end = NULL;

    if ((cfg->priv->sec = strstr(cfg->priv->head, temp)) != NULL) {
        cfg->priv->sec += strlen(temp);
        cfg->priv->sec_end = cfg->priv->sec + 1;

        end = 0;

        while (cfg->priv->sec_end < cfg->priv->tail && !end) {
            if (*cfg->priv->sec_end == '\\') {
                cfg->priv->sec_end += 1;
            }

            end = (*cfg->priv->sec_end == '\n');

            if (end) {
                cfg->priv->sec_end += 1;
                while (cfg->priv->sec_end < cfg->priv->tail && *cfg->priv->sec_end == '\r') {
                    cfg->priv->sec_end += 1;
                }

                end = (*cfg->priv->sec_end == '\n');

                if (end) {
                    continue;
                }
            }

            cfg->priv->sec_end += 1;
        }

        if (cfg->priv->sec_end > cfg->priv->tail) {
            cfg->priv->sec = cfg->priv->sec_end = NULL;
        }
    }

    return (cfg->priv->sec != NULL);
}

void bcrepo_release_config(struct bcrepo_config_ctx *cfg) {
    if (cfg != NULL) {
        if (cfg->priv != NULL && cfg->priv->head != NULL) {
            kryptos_freeseg(cfg->priv->head, cfg->priv->tail - cfg->priv->head);
            kryptos_freeseg(cfg->priv, sizeof(struct bcrepo_config_priv_ctx));
            kryptos_freeseg(cfg, sizeof(struct bcrepo_config_ctx));
        }
    }
}

int bcrepo_config_get_next_line(struct bcrepo_config_ctx *cfg) {
    if (cfg == NULL || cfg->priv->sec == NULL) {
        return 0;
    }

    if (cfg->line == NULL || cfg->line_end == NULL) {
        cfg->line = cfg->line_end = cfg->priv->sec + (*cfg->priv->sec == '\n');
    } else {
        cfg->line_end += 1;
        cfg->line = cfg->line_end;
        cfg->line_end += 1;
    }

    if (cfg->line_end >= cfg->priv->sec_end) {
        cfg->line_end = cfg->line = NULL;
        return 0;
    }

    while (cfg->line_end != cfg->priv->sec_end && *cfg->line_end != '\n') {
        cfg->line_end += 1;
    }

    return 1;
}

int bcrepo_config_get_next_word(struct bcrepo_config_ctx *cfg) {
    if (cfg == NULL || cfg->priv->sec == NULL) {
        return 0;
    }

    if (cfg->word == NULL || cfg->word_end == NULL) {
        cfg->word = cfg->word_end = cfg->priv->sec + (*cfg->priv->sec == '\n');
    } else {
        cfg->word_end += 1;
        cfg->word = cfg->word_end;
        cfg->word_end += 1;
    }

    if (cfg->word >= cfg->priv->sec_end) {
        cfg->word_end = cfg->word = NULL;
        return 0;
    }

    while (cfg->word_end != cfg->priv->sec_end && *cfg->word_end != ' ' && *cfg->word_end != '\n') {
        cfg->word_end += 1;
    }

    return 1;
}
