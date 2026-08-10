#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct OpaqueState* StateHandle;
struct OpaqueState {
    char buffer[128];
    int initialized;
};
void handle_state(StateHandle handle) {
    if (!handle) return;
    if (handle->initialized) {
        printf("Buffer: %s\n", handle->buffer);
    }
}
int main() {
    struct OpaqueState* s = malloc(sizeof(struct OpaqueState));
    s->initialized = 1;
    handle_state(s);
    free(s);
    return 0;
}
