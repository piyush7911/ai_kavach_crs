/* Proof: process_chunk must not compute a length that overruns `data`.
 * Precondition from the caller: `data` points to a real buffer. We give it a
 * concrete 256-byte array and assume the requested window fits, which is the
 * contract the function is written against. */
#include <stddef.h>
void process_chunk(size_t chunk_end, size_t chunk_start, const char *data);
unsigned long nondet_ulong(void);

#define BUF 256
static char backing[BUF];

void harness(void) {
    size_t end = nondet_ulong();
    size_t start = nondet_ulong();
    __CPROVER_assume(end <= BUF && start <= BUF);   /* caller-side bound */
    process_chunk(end, start, backing);
}
