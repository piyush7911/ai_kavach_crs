#include <stdio.h>
#include <stdlib.h>
typedef union {
    int id;
    char* name;
} UserIdentifier;
void print_user(UserIdentifier uid, int is_string) {
    if (is_string) {
        printf("User name: %s\n", uid.name);
    } else {
    }
}
void process_type_confusion() {
    UserIdentifier uid;
    uid.id = 0x41414141; 
    printf("User name: %s\n", uid.name); 
}
int main() {
    process_type_confusion();
    return 0;
}
