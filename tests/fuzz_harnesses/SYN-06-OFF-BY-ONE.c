/* Fuzz harness for 06_off_by_one_loop.c
 * The bug: loop writes dest[size] on a malloc(size) buffer. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void copy_and_null_terminate(const char* src, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024) return 0;
    char *s = (char *)malloc(size + 1);
    memcpy(s, data, size); s[size] = '\0';
    copy_and_null_terminate(s, size);
    free(s);
    return 0;
}
