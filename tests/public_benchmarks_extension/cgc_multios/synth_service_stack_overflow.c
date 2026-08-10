/*
 * Synthetic service stack overflow.
 *
 * PROVENANCE: original hand-written code, written in the style of a DARPA
 * Cyber Grand Challenge service. It is NOT the CGC CADET_00001 challenge
 * binary and was not derived from the CGC corpus.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 64

typedef struct {
    char header[16];
    char body[MAX_PAYLOAD];
} CGCServicePacket;

void process_cgc_command(const char *cmd_input) {
    CGCServicePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    strcpy(pkt.body, cmd_input);
    printf("CGC Service Command Received: %s\n", pkt.body);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <cmd>\n", argv[0]);
        return 1;
    }
    
    process_cgc_command(argv[1]);
    return 0;
}
