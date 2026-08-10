#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void log_user_activity(const char* username) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "User logged in: %s", username);
    printf(log_msg); 
    printf("\n");
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        log_user_activity(argv[1]);
    }
    return 0;
}
