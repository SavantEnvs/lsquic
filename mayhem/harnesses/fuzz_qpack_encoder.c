/*
 * libFuzzer harness for the ls-qpack QPACK encoder (lsqpack.h public API): lsquic's encoder reads
 * the peer's QPACK decoder stream (lsqpack_enc_decoder_in: Section Acknowledgement, Stream
 * Cancellation, Insert Count Increment) and encodes our own header lists against the dynamic
 * table the peer's instructions keep in sync.
 *
 * Input is a sequence of ops:
 *   0x00 len(1) bytes   -> lsqpack_enc_decoder_in(bytes)         (peer decoder-stream data)
 *   0x01 sid(1) nhdr(1) -> encode one header block on stream sid with nhdr fields; each field is
 *                          flags(1) nlen(1) vlen(1) name value  (taken from the input)
 *   other               -> lsqpack_enc_set_max_capacity(byte*16)
 * One encoder per input.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lsqpack.h"
#include "lsxpack_header.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct lsqpack_enc enc;
    unsigned char sdtc[LSQPACK_LONGEST_SDTC];
    size_t sdtc_sz = sizeof(sdtc);
    static unsigned char enc_buf[0x4000], hdr_buf[0x4000], pfx[64];
    static char hbuf[600];
    const uint8_t *p = data, *end = data + size;
    unsigned seqno = 0;
    int dead = 0;

    if (size < 2)
        return -1;
    lsqpack_enc_preinit(&enc, NULL);
    if (0 != lsqpack_enc_init(&enc, NULL, 0x1000, 0x1000, p[0] % 32,
                              (enum lsqpack_enc_opts) (p[1] & 0x1f), sdtc, &sdtc_sz))
        return 0;
    p += 2;

    while (p < end && !dead)
    {
        uint8_t op = *p++;
        if (op == 0x00)
        {
            size_t len;
            if (p >= end) break;
            len = *p++;
            if (len > (size_t) (end - p)) len = (size_t) (end - p);
            if (0 != lsqpack_enc_decoder_in(&enc, p, len))
                dead = 1;   /* decoder-stream error is fatal for the connection */
            p += len;
        }
        else if (op == 0x01)
        {
            unsigned sid, nhdr, i;
            if (end - p < 2) break;
            sid = *p++; nhdr = *p++;
            if (0 != lsqpack_enc_start_header(&enc, sid, seqno++))
                break;
            for (i = 0; i < nhdr && end - p >= 3; ++i)
            {
                struct lsxpack_header xhdr;
                size_t esz = sizeof(enc_buf), hsz = sizeof(hdr_buf);
                unsigned flags = p[0] & 0x0f, nlen = p[1], vlen = p[2];
                p += 3;
                if (nlen + vlen > (size_t) (end - p)) break;
                memcpy(hbuf, p, nlen + vlen);
                p += nlen + vlen;
                lsxpack_header_set_offset2(&xhdr, hbuf, 0, nlen, nlen, vlen);
                (void) lsqpack_enc_encode(&enc, enc_buf, &esz, hdr_buf, &hsz,
                                          &xhdr, (enum lsqpack_enc_flags) flags);
            }
            if (lsqpack_enc_end_header(&enc, pfx, sizeof(pfx), NULL) < 0)
                (void) lsqpack_enc_cancel_header(&enc);
        }
        else
        {
            sdtc_sz = sizeof(sdtc);
            (void) lsqpack_enc_set_max_capacity(&enc, (unsigned) op * 16, sdtc, &sdtc_sz);
        }
    }
    lsqpack_enc_cleanup(&enc);
    return 0;
}
