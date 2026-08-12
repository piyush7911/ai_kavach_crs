/* Driver for CVE-2019-11835 in cJSON.
 *
 * Exercises cJSON_Minify() on a heap copy of argv[1]. Heap rather than stack so
 * AddressSanitizer can observe the over-read: the vulnerable loop walks past the
 * NUL terminator of an unterminated block comment.
 *
 * This is the real upstream function, not a reproduction. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON.h"

int main(int argc, char **argv) {
    const char *src = (argc > 1) ? argv[1] : "{}";
    char *heap = strdup(src);
    if (!heap) return 1;
    cJSON_Minify(heap);
    printf("minified: %s\n", heap);
    free(heap);
    return 0;
}
