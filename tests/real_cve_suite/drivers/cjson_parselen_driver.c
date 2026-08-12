/* Driver for the parse_object trailing-comma heap over-read.
 *
 * Mirrors upstream's own regression test (tests/parse_examples.c,
 * test15_should_not_heap_buffer_overflow): the input is copied into an
 * allocation of EXACTLY strlen(input) bytes — deliberately NOT NUL-terminated —
 * and handed to cJSON_ParseWithLength.
 *
 * That matters: with cJSON_Parse the buffer carries a NUL and length strlen+1,
 * so the parser stops harmlessly. Only the exact-size, unterminated case lets
 * the missing `cannot_access_at_index` check read past the allocation. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON.h"

int main(int argc, char **argv) {
    const char *src = (argc > 1) ? argv[1] : "{}";
    size_t len = strlen(src);

    char *exact = (char *)malloc(len ? len : 1);
    if (!exact) return 1;
    memcpy(exact, src, len);            /* no NUL terminator, by design */

    cJSON *item = cJSON_ParseWithLength(exact, len);
    printf("parsed: %s\n", item ? "ok" : "null");

    cJSON_Delete(item);
    free(exact);
    return 0;
}
