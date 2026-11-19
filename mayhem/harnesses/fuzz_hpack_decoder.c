/*
 * libFuzzer harness for the ls-hpack HPACK decoder (lshpack.h public API), which lsquic uses to
 * decode gQUIC HTTP/2-style HEADERS/PUSH_PROMISE blocks from the peer.
 *
 * Input byte 0 selects the dynamic table capacity (lshpack_dec_set_max_capacity, 0..255*64 bytes);
 * the rest is one header block decoded field by field until it is consumed or an error occurs.
 * A fresh decoder per input.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lshpack.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct lshpack_dec dec;
    struct lsxpack_header xhdr;
    static char buf[0x10000];
    const unsigned char *p, *end;
    volatile unsigned sum = 0;

    if (size < 1)
        return -1;
    lshpack_dec_init(&dec);
    lshpack_dec_set_max_capacity(&dec, (unsigned) data[0] * 64);
    p = data + 1;
    end = data + size;
    while (p < end)
    {
        lsxpack_header_prepare_decode(&xhdr, buf, 0, sizeof(buf));
        if (0 != lshpack_dec_decode(&dec, &p, end, &xhdr))
            break;
        for (unsigned i = 0; i < xhdr.name_len; ++i)
            sum += (unsigned char) buf[xhdr.name_offset + i];
        for (unsigned i = 0; i < xhdr.val_len; ++i)
            sum += (unsigned char) buf[xhdr.val_offset + i];
    }
    (void) sum;
    lshpack_dec_cleanup(&dec);
    return 0;
}
