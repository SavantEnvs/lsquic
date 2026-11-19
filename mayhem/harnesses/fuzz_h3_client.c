/*
 * libFuzzer harness: the reverse of fuzz_h3_loopback. An in-process lsquic HTTP/3 *client*
 * engine (LSENG_HTTP, QUIC v1) talks to an in-process plain lsquic server engine (no
 * LSENG_HTTP, ALPN "h3") over ea_packets_out, with a real TLS handshake. The client sends one
 * GET per record with lsquic_stream_send_headers(); the server answers each request stream by
 * writing that record's fuzz bytes verbatim. So the client parses attacker-controlled HTTP/3
 * responses: HEADERS/DATA/reserved and unknown frames in lsquic_stream.c, QPACK header blocks
 * through lsquic_qdec_hdl.c and ls-qpack, and response conversion in lsquic_http1x_if.c.
 *
 * Input: repeated  flags(1) | len(2, big endian) | len bytes  ; each record is one request and
 * its response bytes. flags bit 0: FIN after the response; bit 1: write the response in two
 * halves, pumping in between; bit 2: drop the next server-to-client datagram; bit 3: reset the
 * stream after writing. At most 16 requests. Fresh engines per input.
 */
#include "engine_common.h"
#include "lsxpack_header.h"

#define MAX_DGRAMS 256
#define MAX_STREAMS 16

struct dgram { size_t len; unsigned char buf[1500]; };
struct queue { unsigned n; struct dgram d[MAX_DGRAMS]; };

struct chunk
{
    const uint8_t  *buf;
    size_t          len, off;
    unsigned        flags;
    int             done;
    lsquic_stream_t *stream;                /* NULL once closed */
};

static struct queue s_to_server, s_to_client;
static struct chunk s_chunks[MAX_STREAMS];
static unsigned s_n_chunks, s_next_chunk;
static int s_hsk_done, s_drop_next, s_split_pause;
static lsquic_conn_t *s_client_conn;

static int
enqueue (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    struct queue *q = ctx;
    for (unsigned i = 0; i < n; ++i)
    {
        struct dgram *d;
        if (q == &s_to_client && s_drop_next)
        {
            s_drop_next = 0;
            continue;
        }
        if (q->n >= MAX_DGRAMS)
            continue;                       /* the network drops it */
        d = &q->d[q->n];
        d->len = 0;
        for (size_t j = 0; j < specs[i].iovlen; ++j)
        {
            size_t l = specs[i].iov[j].iov_len;
            if (d->len + l > sizeof(d->buf))
                l = sizeof(d->buf) - d->len;
            memcpy(d->buf + d->len, specs[i].iov[j].iov_base, l);
            d->len += l;
        }
        ++q->n;
    }
    return (int) n;
}

static void
deliver (lsquic_engine_t *engine, struct queue *q, const struct sockaddr *local,
         const struct sockaddr *peer)
{
    unsigned n = q->n;
    static struct dgram tmp[MAX_DGRAMS];
    memcpy(tmp, q->d, sizeof(tmp[0]) * n);
    q->n = 0;
    for (unsigned i = 0; i < n; ++i)
        (void) lsquic_engine_packet_in(engine, tmp[i].buf, tmp[i].len, local, peer, NULL, 0);
}

/* client callbacks */
static lsquic_conn_ctx_t *
cl_on_new_conn (void *ctx, lsquic_conn_t *c)
{
    (void) ctx;
    s_client_conn = c;
    return NULL;
}

static void
cl_on_conn_closed (lsquic_conn_t *c)
{
    if (c == s_client_conn)
        s_client_conn = NULL;
}

static void
cl_on_hsk_done (lsquic_conn_t *c, enum lsquic_hsk_status st)
{
    (void) c;
    s_hsk_done = (st == LSQ_HSK_OK || st == LSQ_HSK_RESUMED_OK) ? 1 : -1;
}

/* Client side: each new request stream sends a fixed GET and then reads the response. */
static lsquic_stream_ctx_t *
cl_on_new_stream (void *ctx, lsquic_stream_t *s)
{
    (void) ctx;
    if (s)
        lsquic_stream_wantwrite(s, 1);
    return NULL;
}

static void
cl_on_write_request (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    static char hbuf[] = ":methodGET:schemehttps:path/:authoritylocalhost";
    struct lsxpack_header xh[4];
    struct lsquic_http_headers headers = { 4, xh };
    (void) h;
    lsxpack_header_set_offset2(&xh[0], hbuf, 0, 7, 7, 3);
    lsxpack_header_set_offset2(&xh[1], hbuf, 10, 7, 17, 5);
    lsxpack_header_set_offset2(&xh[2], hbuf, 22, 5, 27, 1);
    lsxpack_header_set_offset2(&xh[3], hbuf, 28, 10, 38, 9);
    lsquic_stream_wantwrite(s, 0);
    if (0 == lsquic_stream_send_headers(s, &headers, 0))
        lsquic_stream_shutdown(s, 1);
    lsquic_stream_wantread(s, 1);
}

/* Server side: the n-th request stream carries the n-th fuzz record as its response. */
static lsquic_stream_ctx_t *
sv_on_new_stream (void *ctx, lsquic_stream_t *s)
{
    (void) ctx;
    if (!s)
        return NULL;
    lsquic_stream_wantread(s, 1);
    /* only client-initiated bidirectional (request) streams: id % 4 == 0 */
    if (s_next_chunk < s_n_chunks && (lsquic_stream_id(s) & 3) == 0)
    {
        struct chunk *ch = &s_chunks[s_next_chunk++];
        ch->stream = s;
        lsquic_stream_wantwrite(s, 1);
        return (lsquic_stream_ctx_t *) ch;
    }
    return NULL;
}

static void
sv_on_read (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    unsigned char buf[0x1000];
    ssize_t n;
    (void) h;
    while ((n = lsquic_stream_read(s, buf, sizeof(buf))) > 0)
        ;
    if (n <= 0)
        lsquic_stream_wantread(s, 0);
}

static void
cl_on_write (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    struct chunk *ch = (struct chunk *) h;
    size_t want;
    ssize_t nw;

    if (!ch || ch->done)
    {
        lsquic_stream_wantwrite(s, 0);
        return;
    }
    want = ch->len - ch->off;
    if ((ch->flags & 2) && ch->off < ch->len / 2)
        want = ch->len / 2 - ch->off;
    nw = want ? lsquic_stream_write(s, ch->buf + ch->off, want) : 0;
    if (nw < 0)
    {
        ch->done = 1;
        lsquic_stream_wantwrite(s, 0);
        return;
    }
    ch->off += (size_t) nw;
    lsquic_stream_flush(s);
    if ((ch->flags & 2) && ch->off == ch->len / 2 && ch->off < ch->len)
    {
        lsquic_stream_wantwrite(s, 0);      /* resumed by the pump: data split across packets */
        s_split_pause = 1;
        return;
    }
    if (ch->off >= ch->len)
    {
        ch->done = 1;
        lsquic_stream_wantwrite(s, 0);
        if (ch->flags & 8)
            lsquic_stream_close(s);
        else if (ch->flags & 1)
            lsquic_stream_shutdown(s, 1);
    }
}

static void
cl_on_close (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void) s;
    if (h)
        ((struct chunk *) h)->stream = NULL;
}

static const struct lsquic_stream_if s_client_stream_if = {
    .on_new_conn    = cl_on_new_conn,
    .on_conn_closed = cl_on_conn_closed,
    .on_hsk_done    = cl_on_hsk_done,
    .on_new_stream  = cl_on_new_stream,
    .on_read        = fuzz_on_read,
    .on_write       = cl_on_write_request,
    .on_close       = fuzz_on_close,
};

static const struct lsquic_stream_if s_plain_server_stream_if = {
    .on_new_conn    = fuzz_on_new_conn,
    .on_conn_closed = fuzz_on_conn_closed,
    .on_new_stream  = sv_on_new_stream,
    .on_read        = sv_on_read,
    .on_write       = cl_on_write,
    .on_close       = cl_on_close,
};

static lsquic_engine_t *
new_engine (unsigned flags, struct lsquic_engine_settings *st, struct queue *out)
{
    struct lsquic_engine_api api;
    lsquic_engine_init_settings(st, flags);
    st->es_versions = 1u << LSQVER_I001;
    st->es_pace_packets = 0;                /* pacing would wait on the wall clock */
    st->es_ql_bits = 0;
    memset(&api, 0, sizeof(api));
    api.ea_settings = st;
    api.ea_packets_out = enqueue;
    api.ea_packets_out_ctx = out;
    if (flags & LSENG_SERVER)
    {
        api.ea_stream_if = &s_plain_server_stream_if;
        api.ea_get_ssl_ctx = fuzz_get_ssl_ctx;
        api.ea_lookup_cert = fuzz_lookup_cert;
    }
    else
    {
        api.ea_stream_if = &s_client_stream_if;
    }
    return lsquic_engine_new(flags, &api);
}

static void
pump (lsquic_engine_t *client, lsquic_engine_t *server, unsigned rounds)
{
    for (unsigned i = 0; i < rounds; ++i)
    {
        lsquic_engine_process_conns(client);
        deliver(server, &s_to_server, (struct sockaddr *) &s_server_sa,
                (struct sockaddr *) &s_client_sa);
        lsquic_engine_process_conns(server);
        deliver(client, &s_to_client, (struct sockaddr *) &s_client_sa,
                (struct sockaddr *) &s_server_sa);
        if (s_to_server.n == 0 && s_to_client.n == 0
                && !lsquic_engine_has_unsent_packets(client)
                && !lsquic_engine_has_unsent_packets(server) && !s_split_pause)
            break;
    }
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_global_init();
    fuzz_init_addrs();
    return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct lsquic_engine_settings cst, sst;
    lsquic_engine_t *client, *server;
    const uint8_t *p = data, *end = data + size;

    s_to_server.n = s_to_client.n = 0;
    s_n_chunks = s_next_chunk = 0;
    s_hsk_done = s_drop_next = s_split_pause = 0;
    s_client_conn = NULL;
    memset(s_chunks, 0, sizeof(s_chunks));
    while (end - p >= 3 && s_n_chunks < MAX_STREAMS)
    {
        struct chunk *ch = &s_chunks[s_n_chunks++];
        ch->flags = p[0];
        ch->len = ((size_t) p[1] << 8) | p[2];
        p += 3;
        if (ch->len > (size_t) (end - p))
            ch->len = (size_t) (end - p);
        ch->buf = p;
        p += ch->len;
    }

    server = new_engine(LSENG_SERVER, &sst, &s_to_client);
    client = new_engine(LSENG_HTTP, &cst, &s_to_server);
    if (!server || !client)
        abort();
    (void) lsquic_engine_connect(client, LSQVER_I001, (struct sockaddr *) &s_client_sa,
                    (struct sockaddr *) &s_server_sa, NULL, NULL, "localhost", 0,
                    NULL, 0, NULL, 0);
    pump(client, server, 32);

    if (s_hsk_done == 1 && s_client_conn)
    {
        for (unsigned i = 0; i < s_n_chunks && s_client_conn; ++i)
        {
            if (s_chunks[i].flags & 4)
                s_drop_next = 1;
            lsquic_conn_make_stream(s_client_conn);
            pump(client, server, 8);
            if (s_split_pause)
            {
                s_split_pause = 0;
                /* resume the stream that paused after its first half */
                for (unsigned j = 0; j < s_next_chunk; ++j)
                    if (!s_chunks[j].done && (s_chunks[j].flags & 2))
                    {
                        s_chunks[j].flags &= ~2u;
                        if (s_chunks[j].stream)
                            lsquic_stream_wantwrite(s_chunks[j].stream, 1);
                    }
                pump(client, server, 8);
            }
        }
        pump(client, server, 16);
    }

    lsquic_engine_destroy(client);
    lsquic_engine_destroy(server);
    return 0;
}
