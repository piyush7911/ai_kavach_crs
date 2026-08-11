/* Fuzz harness for 05_double_free_conditional.c
 * The bug: process_data() frees `buffer` early when it equals "ERROR", then
 * unconditionally frees it again at the end of the function. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void process_data(const char* input);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 256) return 0;
    char *s = (char *)malloc(size + 1);
    memcpy(s, data, size);
    s[size] = '\0';
    process_data(s);
    free(s);
    return 0;
}
