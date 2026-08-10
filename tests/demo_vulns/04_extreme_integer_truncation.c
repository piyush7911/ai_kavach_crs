#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef struct {
    uint32_t magic;
    uint32_t object_size;
    char* data;
} LegacyHeader;
void parse_legacy_object(size_t incoming_size, const char* incoming_data) {
    if (!incoming_data || incoming_size == 0) return;
    LegacyHeader* header = (LegacyHeader*)malloc(sizeof(LegacyHeader));
    if (!header) return;
    header->magic = 0xCAFEBABE;
    header->object_size = (uint32_t)incoming_size; 
    header->data = (char*)malloc(header->object_size);
    if (!header->data) {
        free(header);
        return;
    }
    memcpy(header->data, incoming_data, incoming_size);
    printf("Parsed legacy object of size %u\n", header->object_size);
    free(header->data);
    free(header);
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <size>\n", argv[0]);
        return 1;
    }
    size_t size = (size_t)strtoull(argv[1], NULL, 10);
    char* dummy_data = (char*)malloc(100);
    parse_legacy_object(size, dummy_data);
    free(dummy_data);
    return 0;
}
