#include <stdio.h>
#include <stdlib.h>
typedef struct {
    int id;
    int index;
} UserRequest;
char* secrets[] = {"Secret1", "Secret2", "Secret3"};
void handle_request(int req_id) {
    UserRequest req; 
    req.id = req_id;
    if (req.index >= 0 && req.index < 3) { 
        printf("Secret: %s\n", secrets[req.index]); 
    }
}
int main(int argc, char* argv[]) {
    if (argc == 2) handle_request(atoi(argv[1]));
    return 0;
}
