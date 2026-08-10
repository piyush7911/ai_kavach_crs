#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int process_transaction(int amount) {
    char* log_msg = (char*)malloc(256);
    if (!log_msg) return -1;
    snprintf(log_msg, 256, "Processing %d", amount);
    if (amount < 0) {
        printf("Error: Negative amount.\n");
        return -1; 
    }
    printf("%s\n", log_msg);
    free(log_msg);
    return 0;
}
int main(int argc, char* argv[]) {
    if (argc == 2) process_transaction(atoi(argv[1]));
    return 0;
}
