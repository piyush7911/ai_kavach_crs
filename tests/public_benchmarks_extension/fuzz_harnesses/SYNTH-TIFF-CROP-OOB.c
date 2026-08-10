/* Fuzz harness for synth_tiff_crop_oob.c
 *
 * Enables adversarial re-fuzzing to harden a crop-box validation fix. The bug
 * class is an out-of-bounds READ, so a crash is the observable failure and
 * libFuzzer + ASan can falsify a patch that validates incompletely.
 *
 * PRECONDITION: process_crop_box() reads img->data indexed by img->width, so
 * the image it is given must be internally consistent. This harness builds the
 * same 10x10 / 100-element image the program's own main() builds, and varies
 * only the attacker-controlled crop dimensions. A harness that supplied a
 * smaller buffer than img->width implies would make the function unfixable by
 * contract and produce false hardening failures.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t width;
    uint32_t height;
    uint16_t bits_per_sample;
    uint32_t *data;
} TIFFCropImage;

int process_crop_box(TIFFCropImage *img, uint32_t box_w, uint32_t box_h);

#define IMG_DIM 10

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint16_t raw_w, raw_h;
    memcpy(&raw_w, data, 2);
    memcpy(&raw_h, data + 2, 2);

    /* Bounded so the allocation stays small; still spans valid and invalid
       dimensions on both sides of the image's real extent. */
    uint32_t box_w = raw_w % 64;
    uint32_t box_h = raw_h % 64;

    TIFFCropImage img;
    img.width = IMG_DIM;
    img.height = IMG_DIM;
    img.bits_per_sample = 32;
    img.data = (uint32_t *)malloc(IMG_DIM * IMG_DIM * sizeof(uint32_t));
    if (!img.data) return 0;
    memset(img.data, 0xAA, IMG_DIM * IMG_DIM * sizeof(uint32_t));

    process_crop_box(&img, box_w, box_h);

    free(img.data);
    return 0;
}
