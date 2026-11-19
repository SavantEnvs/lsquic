/*
 * libFuzzer harness for the ls-qpack QPACK decoder (lsqpack.h public API), the code lsquic uses
 * for every HTTP/3 header block and encoder-stream byte it receives from a peer.
 *
 * Input: the record format of ls-qpack's own AFL driver (bin/fuzz-decode.c), repeated:
 *     u64 stream_id (big endian) | u32 size (big endian) | size bytes
 * stream_id 0 = encoder-stream data (lsqpack_dec_enc_in), anything else = a header block
 * (lsqpack_dec_header_in, continued with lsqpack_dec_header_read when it unblocks).
 * A short final record is truncated to what is left, as fuzz-decode does in non-strict mode.
 * The decoder is created and destroyed per input, so no state crosses inputs.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "lsqpack.h"
#include "lsxpack_header.h"

#define MAX_BLOCKS 64

struct hblock
{
    uint64_t                stream_id;
    const unsigned char    *buf;     /* remaining header-block bytes */
    size_t                  left;
    int                     active;  /* decoder holds a reference */
    int                     unblocked;
    struct lsxpack_header   xhdr;
    char                   *hbuf;
    size_t                  hbuf_sz;
};

static struct hblock s_blocks[MAX_BLOCKS];

static void
unblocked (void *ctx)
{
    ((struct hblock *) ctx)->unblocked = 1;
}

static struct lsxpack_header *
prepare_decode (void *ctx, struct lsxpack_header *xhdr, size_t space)
{
    struct hblock *hb = ctx;
    if (space > LSXPACK_MAX_STRLEN)
        return NULL;
    if (xhdr == NULL || space > hb->hbuf_sz)
    {
        char *nb = realloc(hb->hbuf, space ? space : 1);
        if (!nb)
            return NULL;
        hb->hbuf = nb;
        hb->hbuf_sz = space ? space : 1;
    }
    if (xhdr == NULL)
        lsxpack_header_prepare_decode(&hb->xhdr, hb->hbuf, 0, hb->hbuf_sz);
    else
    {
        hb->xhdr.buf = hb->hbuf;
        hb->xhdr.val_len = (lsxpack_strlen_t) hb->hbuf_sz;
    }
    return &hb->xhdr;
}

static int
process_header (void *ctx, struct lsxpack_header *xhdr)
{
    /* Touch the decoded name and value so ASan sees any bad bounds. */
    volatile unsigned sum = 0;
    const char *name = lsxpack_header_get_name(xhdr);
    const char *val = lsxpack_header_get_value(xhdr);
    for (unsigned i = 0; i < xhdr->name_len; ++i) sum += (unsigned char) name[i];
    for (unsigned i = 0; i < xhdr->val_len; ++i) sum += (unsigned char) val[i];
    (void) sum;
    return 0;
}

static const struct lsqpack_dec_hset_if hset_if = {
    .dhi_unblocked      = unblocked,
    .dhi_prepare_decode = prepare_decode,
    .dhi_process_header = process_header,
};

static void
feed (struct lsqpack_dec *dec, struct hblock *hb, int first)
{
    unsigned char dec_buf[LSQPACK_LONGEST_HEADER_ACK];
    size_t dec_buf_sz = sizeof(dec_buf);
    const unsigned char *p = hb->buf;
    enum lsqpack_read_header_status rhs;

    if (first)
        rhs = lsqpack_dec_header_in(dec, hb, hb->stream_id, hb->left, &p,
                                    hb->left, dec_buf, &dec_buf_sz);
    else
        rhs = lsqpack_dec_header_read(dec, hb, &p, hb->left, dec_buf,
                                      &dec_buf_sz);
    hb->left -= (size_t) (p - hb->buf);
    hb->buf = p;
    hb->active = (rhs == LQRHS_BLOCKED || rhs == LQRHS_NEED);
    hb->unblocked = 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct lsqpack_dec dec;
    const unsigned char *p = data, *end = data + size;
    unsigned n_blocks = 0, i;
    unsigned char ici[16];

    memset(s_blocks, 0, sizeof(s_blocks));
    lsqpack_dec_init(&dec, NULL, 0x1000, 100, &hset_if, 0);

    while (end - p > 12)
    {
        uint64_t stream_id = 0;
        uint32_t rsize = 0;
        for (i = 0; i < 8; ++i) stream_id = (stream_id << 8) | *p++;
        for (i = 0; i < 4; ++i) rsize = (rsize << 8) | *p++;
        if (rsize > (uint32_t) (end - p))
            rsize = (uint32_t) (end - p);
        if (stream_id == 0)
        {
            if (0 != lsqpack_dec_enc_in(&dec, p, rsize))
                break;  /* encoder-stream error is fatal for the connection */
            for (i = 0; i < n_blocks; ++i)
                if (s_blocks[i].active && s_blocks[i].unblocked)
                    feed(&dec, &s_blocks[i], 0);
            (void) lsqpack_dec_write_ici(&dec, ici, sizeof(ici));
        }
        else if (n_blocks < MAX_BLOCKS)
        {
            struct hblock *hb = &s_blocks[n_blocks++];
            hb->stream_id = stream_id;
            hb->buf = p;
            hb->left = rsize;
            feed(&dec, hb, 1);
        }
        p += rsize;
    }

    for (i = 0; i < n_blocks; ++i)
        if (s_blocks[i].active)
            (void) lsqpack_dec_unref_stream(&dec, &s_blocks[i]);
    lsqpack_dec_cleanup(&dec);
    for (i = 0; i < n_blocks; ++i)
        free(s_blocks[i].hbuf);
    return 0;
}
