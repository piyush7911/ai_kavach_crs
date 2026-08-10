#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtos_types.h"

static SessionHandle g_session;

void async_cleanup_callback(void) {
    if (g_session.is_active && g_session.active_pkt) {
        printf("Cleanup magic: 0x%x\n", g_session.active_pkt->magic);
    }
}

int handle_client_request(const char *input) {
    ChannelPacket *pkt = (ChannelPacket *)malloc(sizeof(ChannelPacket));
    if (!pkt) return -1;
    
    memset(pkt, 0, sizeof(ChannelPacket));
    pkt->magic = RTOS_HEADER_MAGIC;
    
    g_session.active_pkt = pkt;
    g_session.is_active = 1;
    
    if (strcmp(input, "ERR_INVALID") == 0) {
        free(pkt);
        async_cleanup_callback();
        return -1;
    }
    
    async_cleanup_callback();
    free(pkt);
    g_session.active_pkt = NULL;
    g_session.is_active = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input_str>\n", argv[0]);
        return 1;
    }
    
    handle_client_request(argv[1]);
    return 0;
}
