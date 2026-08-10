#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void read_user_file(const char* filename) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "/var/www/html/users/%s", filename);
    FILE* f = fopen(filepath, "r"); 
    if (f) {
        printf("Successfully opened %s\n", filepath);
        fclose(f);
    } else {
        printf("Failed to open %s\n", filepath);
    }
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        read_user_file(argv[1]);
    }
    return 0;
}
