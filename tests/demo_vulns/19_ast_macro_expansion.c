#include <stdio.h>
#include <stdlib.h>
#define ALLOC_NODE(type) (type*)malloc(sizeof(type))
#define SAFE_FREE(ptr) if(ptr) { free(ptr); ptr = NULL; }
typedef struct Node {
    int data;
    struct Node* next;
} Node;
void process_node(Node* head) {
    if (!head) return;
    Node* current = head;
    SAFE_FREE(current);
    if (current && current->data == 0) {
        printf("Data is zero\n");
    }
}
int main() {
    Node* n = ALLOC_NODE(Node);
    n->data = 0;
    n->next = NULL;
    process_node(n);
    return 0;
}
