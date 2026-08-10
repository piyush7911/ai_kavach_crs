/* Fuzz harness for 12_integer_underflow.c
 *
 * The bug: `chunk_end - chunk_start` underflows size_t into a huge length.
 *
 * PRECONDITION (important): process_chunk() takes no length for `data`, so the
 * caller must supply a buffer holding at least `chunk_end - chunk_start` bytes.
 * A harness that violates this makes the function unfixable — any patch would
 * still read past a too-small buffer — and would blame the agent for our bug.
 * The backing buffer is therefore sized to the maximum length the harness can
 * request (end < 4096), so a correct underflow fix genuinely makes it safe.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void process_chunk(size_t chunk_end, size_t chunk_start, const char* data);

#define MAX_CHUNK 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    uint32_t end, start;
    memcpy(&end, data, 4);
    memcpy(&start, data + 4, 4);

    static char backing[MAX_CHUNK];
    memset(backing, 'A', sizeof(backing));

    /* end/start stay inside MAX_CHUNK, so the legitimate length can never
       exceed the buffer. Only the underflow path produces an oversized read. */
    process_chunk((size_t)(end % MAX_CHUNK), (size_t)(start % MAX_CHUNK), backing);
    return 0;
}
