/* Fuzz harness for 11_oob_multidim_array.c
 * The bug: read_matrix() bounds-checks `row` but not `col`, so any col value
 * indexes past the global 5x5 array. `row` is folded into [0,4] here so the
 * harness always reaches the unchecked column read instead of bouncing off
 * the row guard. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int read_matrix(int row, int col);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    int32_t row, col;
    memcpy(&row, data, 4);
    memcpy(&col, data + 4, 4);
    row = ((row % 5) + 5) % 5;
    read_matrix(row, col);
    return 0;
}
