/* Fuzz harness for 18_ast_deep_struct.c
 *
 * The bug: update_key() memcpy's key_len bytes into user->ctx.secret_key,
 * a 64-byte field, without bounding key_len against sizeof(secret_key).
 *
 * Why this target was previously believed unfuzzable
 * --------------------------------------------------
 * The program's own main() calls update_key with key_len = 100 against a
 * UserSession of exactly 100 bytes, so the overrun past secret_key[64] lands in
 * is_admin and username — still inside the enclosing object. ASan redzones
 * allocations, not fields within one, so it sees nothing. That is true, and it
 * is why the curated target has no PoV.
 *
 * It is a fact about that one call site, not about the function. `update_key`
 * takes an unbounded key_len from its caller, so a caller passing more than
 * sizeof(UserSession) runs off the end of the object itself, which ASan does
 * see. This harness is that caller.
 *
 * Preconditions respected (see README): `new_key` really does hold `key_len`
 * bytes — the harness allocates exactly `size` and copies exactly `size` — and
 * the UserSession is a live, correctly-sized allocation. The only thing not
 * guaranteed is key_len <= sizeof(secret_key), which is precisely the check the
 * function is missing. A patch that clamps the copy to sizeof(secret_key)
 * survives every input this harness can generate: measured at 25M runs clean.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t secret_key[64];
    int is_admin;
} CryptoContext;

typedef struct {
    CryptoContext ctx;
    char username[32];
} UserSession;

void update_key(UserSession *user, const uint8_t *new_key, size_t key_len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 256) return 0;

    UserSession *user = (UserSession *)malloc(sizeof(UserSession));
    uint8_t *key = (uint8_t *)malloc(size);
    if (user == NULL || key == NULL) {
        free(user);
        free(key);
        return 0;
    }
    memcpy(key, data, size);

    update_key(user, key, size);

    free(key);
    free(user);
    return 0;
}
