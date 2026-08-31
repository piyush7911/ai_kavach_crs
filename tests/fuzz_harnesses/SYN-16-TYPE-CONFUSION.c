/* Fuzz harness for 16_type_confusion.c
 *
 * The bug: render_user() populates the union's `id` member from atoi(), then
 * reads the `name` member and passes it to %s — dereferencing an integer as a
 * pointer. The confusion is created and consumed entirely inside the function,
 * so a patch confined to that function can fix it.
 *
 * Precondition respected: render_user() takes a NUL-terminated string and only
 * calls atoi() on it, so any printable byte sequence is a legitimate input.
 *
 * The earlier harness targeted print_user(uid, is_string) and passed
 * is_string=1 while populating uid.id. That asserted a fact about the union the
 * caller had made false, and no patch inside print_user could detect it — the
 * function was unfixable by contract, so re-fuzzing reported a "new crash" for
 * every correct patch. See tests/fuzz_harnesses/README.md.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

void render_user(const char *raw);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 64) return 0;
    char buf[65];
    memcpy(buf, data, size);
    buf[size] = '\0';
    render_user(buf);
    return 0;
}
