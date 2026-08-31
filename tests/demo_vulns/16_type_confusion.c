#include <stdio.h>
#include <stdlib.h>
typedef union {
    int id;
    char* name;
} UserIdentifier;
void render_user(const char* raw) {
    UserIdentifier uid;
    uid.id = atoi(raw);
    printf("User name: %s\n", uid.name);
}
int main(int argc, char* argv[]) {
    render_user(argc > 1 ? argv[1] : "1094795585");
    return 0;
}
