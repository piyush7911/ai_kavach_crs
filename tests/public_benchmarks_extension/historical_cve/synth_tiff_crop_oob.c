/*
 * Synthetic crop-box out-of-bounds read.
 *
 * PROVENANCE: original hand-written code. This reproduces the SHAPE of the
 * LibTIFF crop-box bug (CVE-2016-5321) — a copy loop that indexes the source
 * image using requested box dimensions without validating them against the
 * image's real width/height. It is NOT LibTIFF source and NOT that CVE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t width;
    uint32_t height;
    uint16_t bits_per_sample;
    uint32_t *data;
} TIFFCropImage;

int process_crop_box(TIFFCropImage *img, uint32_t box_w, uint32_t box_h) {
    if (!img || !img->data) return -1;
    
    size_t alloc_bytes = box_w * box_h * sizeof(uint32_t);
    uint32_t *crop_buf = (uint32_t *)malloc(alloc_bytes);
    if (!crop_buf) return -1;
    
    for (uint32_t r = 0; r < box_h; r++) {
        for (uint32_t c = 0; c < box_w; c++) {
            crop_buf[r * box_w + c] = img->data[r * img->width + c];
        }
    }
    
    printf("Successfully processed tiff crop box\n");
    free(crop_buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <box_w> <box_h>\n", argv[0]);
        return 1;
    }
    
    uint32_t bw = (uint32_t)strtoul(argv[1], NULL, 10);
    uint32_t bh = (uint32_t)strtoul(argv[2], NULL, 10);
    
    TIFFCropImage img;
    img.width = 10;
    img.height = 10;
    img.bits_per_sample = 32;
    img.data = (uint32_t *)malloc(100 * sizeof(uint32_t));
    memset(img.data, 0xAA, 100 * sizeof(uint32_t));
    
    process_crop_box(&img, bw, bh);
    free(img.data);
    return 0;
}
