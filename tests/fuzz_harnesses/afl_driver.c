/*
 * AI Kavach CRS — shared fuzz driver.
 *
 * Lets one libFuzzer-style harness (LLVMFuzzerTestOneInput) be driven by
 * AFL++ as well: AFL passes a file path via @@, this reads it and hands the
 * bytes to the same entry point libFuzzer calls. Identical harness code is
 * therefore exercised by both engines.
 *
 * Not linked when building for libFuzzer — libFuzzer supplies its own main.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) { fclose(f); return 1; }

    uint8_t *buf = (uint8_t *)malloc((size_t)len > 0 ? (size_t)len : 1);
    if (!buf) { fclose(f); return 1; }

    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf, got);

    free(buf);
    return 0;
}
