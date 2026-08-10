#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_chunk(size_t chunk_end, size_t chunk_start, const char* data) {
    size_t length = chunk_end - chunk_start; 
    char* dest = (char*)malloc(length + 1);
    if (!dest) return;
    memcpy(dest, data, length); 
    dest[length] = '\0';
    printf("Processed chunk.\n");
    free(dest);
}
int main(int argc, char* argv[]) {
    if (argc == 4) {
        process_chunk(atoi(argv[1]), atoi(argv[2]), argv[3]);
    }
    return 0;
}
