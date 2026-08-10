#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtos_types.h"

void process_bitfield_packet(ChannelPacket *pkt, const uint8_t *data, size_t input_len) {
    if (!pkt || !data) return;
    
    size_t copy_size = pkt->header_spec.payload_len;
    if (copy_size > input_len) {
        copy_size = input_len;
    }
    
    memcpy(pkt->buffer, data, copy_size);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <hex_payload_len>\n", argv[0]);
        return 1;
    }
    
    uint32_t val = (uint32_t)strtoul(argv[1], NULL, 16);
    
    ChannelPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = RTOS_HEADER_MAGIC;
    pkt.header_spec.payload_len = val;
    
    uint8_t payload[512];
    memset(payload, 'A', sizeof(payload));
    
    process_bitfield_packet(&pkt, payload, sizeof(payload));
    printf("Processed payload cleanly\n");
    return 0;
}
