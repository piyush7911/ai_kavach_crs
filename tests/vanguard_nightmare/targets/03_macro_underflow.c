#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtos_types.h"

void allocate_and_store(uint32_t count, const uint8_t *raw_bytes, size_t num_bytes) {
    uint32_t alloc_sz = CALC_ALLOC_SZ(count);
    
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    
    memcpy(buf + MACRO_HDR_LEN, raw_bytes, num_bytes);
    printf("Successfully wrote %zu bytes into macro allocated buffer\n", num_bytes);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <count> <hex_data>\n", argv[0]);
        return 1;
    }
    
    uint32_t count = (uint32_t)strtoul(argv[1], NULL, 10);
    size_t data_len = strlen(argv[2]);
    
    allocate_and_store(count, (const uint8_t *)argv[2], data_len);
    return 0;
}
