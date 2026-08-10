#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t checksum;
    uint32_t payload_len;
    char payload[1]; 
} NetworkPacket;
void process_critical_payload(const char* data, size_t len) {
    if (len < sizeof(NetworkPacket)) {
        return;
    }
    NetworkPacket* pkt = (NetworkPacket*)data;
    if (pkt->magic != 0xDEADC0DE) {
        return;
    }
    if (pkt->version != 0x0100) {
        return;
    }
    if ((pkt->checksum ^ 0xBEEF) != 0xAAAA) {
        return;
    }
    uint32_t alloc_size = pkt->payload_len + sizeof(NetworkPacket);
    char* dest = (char*)malloc(alloc_size);
    if (!dest) return;
    memcpy(dest, pkt->payload, pkt->payload_len); 
    printf("Payload processed successfully.\n");
    free(dest);
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload_string>\n", argv[0]);
        return 1;
    }
    process_critical_payload(argv[1], strlen(argv[1]));
    return 0;
}
