/* Fuzz harness for 07_format_string_vuln.c
 * The bug: log_user_activity() passes attacker-controlled text straight to
 * printf() as the format string, not as an argument. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void log_user_activity(const char* username);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 200) return 0;
    char *s = (char *)malloc(size + 1);
    memcpy(s, data, size);
    s[size] = '\0';
    log_user_activity(s);
    free(s);
    return 0;
}
