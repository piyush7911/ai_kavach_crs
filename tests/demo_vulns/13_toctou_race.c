#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void read_secure_file(const char* filepath) {
    if (access(filepath, R_OK) == 0) {
        FILE* f = fopen(filepath, "r"); 
        if (f) {
            printf("File opened successfully.\n");
            fclose(f);
        }
    } else {
        printf("Access denied.\n");
    }
}
int main(int argc, char* argv[]) {
    if (argc == 2) read_secure_file(argv[1]);
    return 0;
}
