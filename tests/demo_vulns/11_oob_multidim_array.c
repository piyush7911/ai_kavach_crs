#include <stdio.h>
#include <stdlib.h>
int matrix[5][5];
int read_matrix(int row, int col) {
    if (row < 0 || row >= 5) {
        return -1;
    }
    return matrix[row][col]; 
}
int main(int argc, char* argv[]) {
    if (argc == 3) {
        printf("Value: %d\n", read_matrix(atoi(argv[1]), atoi(argv[2])));
    }
    return 0;
}
