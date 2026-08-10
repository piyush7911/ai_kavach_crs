#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void ping_host(const char* ip_address) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", ip_address);
    printf("Executing: %s\n", cmd);
    system(cmd); 
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        ping_host(argv[1]);
    }
    return 0;
}
