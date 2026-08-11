/* Fuzz harness for 01_complex_magic_bytes.c
 * The bug: pkt->payload_len is read from the attacker-controlled header and
 * used to memcpy() out of pkt->payload without checking it against how much
 * data actually follows the header in the buffer.
 *
 * The curated benchmark target has no PoV through argv (0x0100 contains a
 * NUL byte, so no C string can carry it). Calling the function directly with
 * raw fuzz bytes has no such restriction, so this harness can prove the bug
 * that the argv entrypoint cannot reach. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void process_critical_payload(const char* data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) return 0;
    char *buf = (char *)malloc(size);
    memcpy(buf, data, size);
    process_critical_payload(buf, size);
    free(buf);
    return 0;
}
