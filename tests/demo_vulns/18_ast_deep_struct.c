#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef struct {
    uint8_t secret_key[64];
    int is_admin;
} CryptoContext;
typedef struct {
    CryptoContext ctx;
    char username[32];
} UserSession;
void update_key(UserSession *user, const uint8_t *new_key, size_t key_len) {
    memcpy(user->ctx.secret_key, new_key, key_len);
}
int main() {
    UserSession user;
    uint8_t payload[100] = {0};
    update_key(&user, payload, 100);
    return 0;
}
