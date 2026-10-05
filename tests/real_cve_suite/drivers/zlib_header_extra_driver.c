/* Driver for CVE-2022-37434 in zlib.
 *
 * inflateGetHeader() lets a caller supply a fixed-size buffer (head.extra,
 * head.extra_max) to receive a gzip header's extra field. The vulnerable
 * inflate() copies into that buffer without checking the buffer bound when the
 * extra field arrives in more than one inflate() call. This driver builds a
 * gzip stream with an extra field larger than the destination buffer and feeds
 * it to inflate() ONE BYTE AT A TIME, which forces the multi-call delivery path
 * the bug needs; feeding it in one call does not reproduce it.
 *
 * This is the real upstream zlib inflate(), not a reproduction. The gzip
 * stream is constructed by hand (no deflate needed): an empty deflate block is
 * valid gzip payload, so the header parser alone exercises the bug.
 *
 * Usage: driver <extra_field_len>   (argv[1] decimal; default 100)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

#define DEST_MAX 16   /* caller's buffer: deliberately much smaller than the extra field */

int main(int argc, char **argv) {
    unsigned ext