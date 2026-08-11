/* Fuzz harness for 16_type_confusion.c
 * The bug: print_user() trusts the `is_string` flag and reads uid.name even
 * when the union was populated as an int. The harness sets the int member
 * from fuzz bytes and always requests the string interpretation, which is
 * exactly how a caller with a mismatched flag would misuse the union. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef union {
    int id;
    char* name;
} UserIdentifier;

void print_user(UserIdentifier uid, int is_string);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    UserIdentifier uid;
    memcpy(&uid.id, data, 4);
    print_user(uid, 1);
    return 0;
}
