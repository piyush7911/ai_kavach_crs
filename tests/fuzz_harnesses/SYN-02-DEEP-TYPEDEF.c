/* Fuzz harness for 02_deep_typedef_confusion.c
 * Reaches initialize_user_crypto() with an attacker-controlled key length.
 * The bug: memcpy into ctx->crypto.key (64 bytes) with unbounded key_len. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef struct { u8 iv[16]; u8 salt[32]; u8 key[64]; } CryptoParams;
typedef struct { u32 session_id; u32 timeout; CryptoParams crypto; } SessionContext;
typedef struct { SessionContext* ctx; u8 is_admin; } UserObject;

void initialize_user_crypto(UserObject* user, const char* provided_key, size_t key_len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) return 0;
    SessionContext session; memset(&session, 0, sizeof(session));
    session.session_id = 12345; session.timeout = 3600;
    UserObject user = { &session, 0 };
    char *key = (char *)malloc(size);
    memcpy(key, data, size);
    initialize_user_crypto(&user, key, size);
    free(key);
    return 0;
}
