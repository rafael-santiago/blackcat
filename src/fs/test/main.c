/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <string.h>
#include <ctx/fsctx.h>

CUTE_DECLARE_TEST_CASE(fs_tests);
CUTE_DECLARE_TEST_CASE(relpath_ctx_tests);

CUTE_TEST_CASE(fs_tests)
    CUTE_RUN_TEST(relpath_ctx_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(relpath_ctx_tests)
    bfs_catalog_relpath_ctx *relpath = NULL, *p;

    relpath = add_file_to_relpath_ctx(relpath, "a/b/c.txt", strlen("a/b/c.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->tail == relpath);
    CUTE_ASSERT(relpath->last == NULL);

    CUTE_ASSERT(relpath->path != NULL);
    CUTE_ASSERT(strcmp(relpath->path, "a/b/c.txt") == 0);
    CUTE_ASSERT(relpath->status == 'U');
    CUTE_ASSERT(relpath->timestamp != NULL);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/c.txt", strlen("a/b/c.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->tail == relpath);
    CUTE_ASSERT(relpath->last == NULL);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/d.txt", strlen("a/b/d.txt"), 'U', "123456789");

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->next != NULL);
    CUTE_ASSERT(relpath->tail == relpath->next);

    CUTE_ASSERT(relpath->next->last == relpath);
    CUTE_ASSERT(relpath->next->path != NULL);
    CUTE_ASSERT(strcmp(relpath->next->path, "a/b/d.txt") == 0);
    CUTE_ASSERT(relpath->next->status == 'U');
    CUTE_ASSERT(relpath->next->timestamp != NULL);
    CUTE_ASSERT(strcmp(relpath->next->timestamp, "123456789") == 0);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/e.txt", strlen("a/b/e.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->next->next != NULL);
    CUTE_ASSERT(relpath->tail == relpath->next->next);

    CUTE_ASSERT(relpath->next->next->last == relpath->next);
    CUTE_ASSERT(relpath->next->next->path != NULL);
    CUTE_ASSERT(strcmp(relpath->next->next->path, "a/b/e.txt") == 0);
    CUTE_ASSERT(relpath->next->next->status == 'U');
    CUTE_ASSERT(relpath->next->next->timestamp != NULL);

    p = relpath;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/z.txt");
    CUTE_ASSERT(relpath == p);

    p = relpath;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/e.txt");
    CUTE_ASSERT(relpath == p);
    CUTE_ASSERT(relpath->next != NULL);
    CUTE_ASSERT(relpath->next->next == NULL);
    CUTE_ASSERT(relpath->head == p);
    CUTE_ASSERT(relpath->tail == relpath->next);

    p = relpath->next;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/c.txt");
    CUTE_ASSERT(relpath == p);
    CUTE_ASSERT(relpath->next == NULL);
    CUTE_ASSERT(relpath->head == p);
    CUTE_ASSERT(relpath->tail == p);

    relpath = del_file_from_relpath_ctx(relpath, "a/b/d.txt");
    CUTE_ASSERT(relpath == NULL);

    // INFO(Rafael): If this function is failing the memory leak check system will detect this malfunction for us.
    //               This function is internally called by del_file_from_relpath_ctx().
    del_bfs_catalog_relpath_ctx(relpath);
CUTE_TEST_CASE_END

CUTE_MAIN(fs_tests);
