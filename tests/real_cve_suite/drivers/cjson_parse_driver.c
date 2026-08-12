/* Driver for CVE-2019-11834 in cJSON.
 *
 * Feeds argv[1] to cJSON_Parse from a heap allocation, so AddressSanitizer can
 * observe the over-read: parse_string evaluated `*input_end != '"'` BEFORE the
 * bounds check, dereferencing one past the buffer on an unterminated string.
 *
 * Real upstream function; the tree is checked out at the commit before the fix. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON.h"

int main(int argc, char **argv) {
    const char *src = (argc > 1) ? argv[1] : "{}";
    char *heap = strdup(src);
    if (!heap) return 1;
    cJSON *item = cJSON_Parse(heap);
    printf("parsed: %s\n", item ? "ok" : "null");
    if (item) cJSON_Delete(item);
    free(heap);
    return 0;
}
