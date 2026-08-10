#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_data(const char* input) {
    char* buffer = (char*)malloc(128);
    if (!buffer) return;
    if (input) {
        strncpy(buffer, input, 127);
        buffer[127] = '\0';
        if (strcmp(buffer, "ERROR") == 0) {
            printf("Error condition hit.\n");
            free(buffer); 
        }
    }
    printf("Processing complete.\n");
    free(buffer); 
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        process_data(argv[1]);
    } else {
        process_data("NORMAL");
    }
    return 0;
}
