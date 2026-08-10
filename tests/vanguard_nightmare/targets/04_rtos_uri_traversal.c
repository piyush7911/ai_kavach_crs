#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_rtos_uri(const char *uri, char *out_path, size_t out_sz) {
    if (!uri || strncmp(uri, "rtos://", 7) != 0) {
        printf("Invalid scheme\n");
        return -1;
    }
    
    const char *path = uri + 7;
    snprintf(out_path, out_sz, "rtos_storage/%s", path);
    
    FILE *f = fopen(out_path, "r");
    if (f) {
        printf("Opened: %s\n", out_path);
        fclose(f);
        return 0;
    }
    
    printf("Access path: %s\n", out_path);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <rtos_uri>\n", argv[0]);
        return 1;
    }
    
    char resolved[512];
    parse_rtos_uri(argv[1], resolved, sizeof(resolved));
    return 0;
}
