#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void encrypt_data(const char* data) {
    const char* secret_key = "SUPER_SECRET_AES_KEY_12345"; 
    printf("Encrypting data '%s' with key '%s'\n", data, secret_key);
}
int main(int argc, char* argv[]) {
    if (argc == 2) encrypt_data(argv[1]);
    return 0;
}
