#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    int id;
    int status;
} ContextObj;
void evaluate_context(int type) {
    ContextObj* ctx = (ContextObj*)malloc(sizeof(ContextObj) * 100000);
    switch(type) {
        case 1:
            ctx[0].status = 1; 
            printf("Context status set to %d\n", ctx[0].status);
            break;
        default:
            printf("Unknown type.\n");
            break;
    }
    if (ctx) {
        free(ctx);
    }
}
int main(int argc, char* argv[]) {
    if (argc > 1) {
        evaluate_context(atoi(argv[1]));
    }
    return 0;
}
