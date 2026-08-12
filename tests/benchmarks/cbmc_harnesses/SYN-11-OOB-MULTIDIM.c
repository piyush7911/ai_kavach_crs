/* Proof: read_matrix must be memory-safe for EVERY (row, col).
 * The program's own main() passes atoi(argv[..]) — i.e. arbitrary ints — so no
 * precondition may be assumed here. */
int read_matrix(int row, int col);
int nondet_int(void);

void harness(void) {
    int row = nondet_int();
    int col = nondet_int();
    read_matrix(row, col);
}
