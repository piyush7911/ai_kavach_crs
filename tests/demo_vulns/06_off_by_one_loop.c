#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_and_null_terminate(const char* src, size_t size) {
    if (size == 0 || size > 1024) return;
    char* dest = (char*)malloc(size);
    if (!dest) return;
    for (size_t i = 0; i <= size; i++) {
        if (i == size) {
            dest[i] = '\0'; 
        } else {
            dest[i] = src[i];
        }
    }
    printf("Copied string: %s\n", dest);
    free(dest);
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        copy_and_null_terminate(argv[1], strlen(argv[1]));
    }
    return 0;
}
