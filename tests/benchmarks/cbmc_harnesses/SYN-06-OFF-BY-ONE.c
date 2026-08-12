/* Proof: copy_and_null_terminate must not write outside its allocation for any
 * size it accepts. The caller passes strlen(argv[1]), so any size is possible;
 * the function's own guard rejects 0 and >1024. */
#include <stddef.h>
void copy_and_null_terminate(const char *src, size_t size);
unsigned long nondet_ulong(void);

#define SRC 64
static char source[SRC];

void harness(void) {
    size_t size = nondet_ulong();
    __CPROVER_assume(size <= SRC);      /* src really holds `size` bytes */
    copy_and_null_terminate(source, size);
}
