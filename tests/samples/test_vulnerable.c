#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    char name[32];
    int age;
    char role[16];
} UserRecord;
void process_user_input(const char *input) {
    char buffer[64];
    strcpy(buffer, input);  
    printf("Processed: %s\n", buffer);
}
typedef struct Node {
    int data;
    struct Node *next;
} Node;
Node* create_node(int data) {
    Node *node = (Node*)malloc(sizeof(Node));
    if (node) {
        node->data = data;
        node->next = NULL;
    }
    return node;
}
void use_after_free_example() {
    Node *node = create_node(42);
    free(node);
    printf("Data: %d\n", node->data);  
}
int read_element(int *array, int size, int index) {
    return array[index];  
}
void process_record(UserRecord *record) {
    printf("Name: %s\n", record->name);  
    printf("Age: %d\n", record->age);
}
int calculate_total_size(int count, int element_size) {
    int total = count * element_size;  
    char *buffer = (char*)malloc(total);
    if (buffer) {
        memset(buffer, 0, total);
        free(buffer);
    }
    return total;
}
void search_logs(const char *username) {
    char cmd[256];
    sprintf(cmd, "grep '%s' /var/log/auth.log", username);  
    system(cmd);
}
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    process_user_input(argv[1]);
    int arr[] = {10, 20, 30, 40, 50};
    printf("Element: %d\n", read_element(arr, 5, 10));  
    process_record(NULL);  
    calculate_total_size(1000000, 1000000);  
    search_logs(argv[1]);  
    return 0;
}
