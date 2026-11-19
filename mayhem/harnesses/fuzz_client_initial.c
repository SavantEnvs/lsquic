/*
 * libFuzzer harness: server-to-client QUIC v1 Initial packets into an lsquic HTTP client engine
 * after lsquic_engine_connect(). The harness captures the client's first flight to learn the
 * DCID it chose and the SCID it uses, then protects fuzz-generated frames with the RFC 9001
 * server Initial keys for that DCID, so they reach the client's full connection
 * (lsquic_full_conn_ietf.c) at the Initial level: ACK frames against the client's sent-packet
 * history (lsquic_send_ctl.c), CRYPTO data into BoringSSL's ServerHello processing via
 * lsquic_enc_sess_ietf.c, PADDING/PING/CONNECTION_CLOSE, and the server-CID switch.
 *
 * Input: repeated  u16 len (big endian) | len bytes  ; each chunk is the plaintext payload of one
 * server Initial (packet numbers 0,1,2...). Length bit 15 marks a raw datagram instead (sent
 * unprotected as-is: Version Negotiation, Retry, stateless reset, garbage); bit 14 makes the
 * client process its timers/output between packets. A fresh engine per input.
 */
#include "engine_common.h"
#include "quic_initial.h"

static const uint8_t s_server_cid[8] = { 0x5e, 0x7e, 0xc1, 0xd0, 0x00, 0x11, 0x22, 0x33 };
static uint8_t s_cl_dcid[20], s_cl_scid[20];
static size_t s_cl_dcid_len, s_cl_scid_len;
static int s_captured;

static int
capture_first (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    (void) ctx;
    if (!s_captured && n > 0 && specs[0].iovlen > 0)
    {
        const uint8_t *b = specs[0].iov[0].iov_base;
        size_t len = specs[0].iov[0].iov_len;
        if (len > 7 && (b[0] & 0xf0) == 0xc0 && b[5] <= 20 && 6u + b[5] + 1 < len)
        {
            s_cl_dcid_len = b[5];
            memcpy(s_cl_dcid, b + 6, s_cl_dcid_len);
            s_cl_scid_len = b[6 + s_cl_dcid_len];
            if (s_cl_scid_len <= 20 && 7 + s_cl_dcid_len + s_cl_scid_len <= len)
            {
                memcpy(s_cl_scid, b + 7 + s_cl_dcid_len, s_cl_scid_len);
                s_captured = 1;
            }
        }
    }
    return (int) n;
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
    static uint8_t pkt[0x4000 + 1500];
    struct lsquic_engine_settings settings;
    struct lsquic_engine_api api;
    struct initial_keys keys;
    lsquic_engine_t *engine;
    const uint8_t *p = data, *end = data + size;
    uint32_t pn = 0;
    unsigned n = 0;

    s_captured = 0;
    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    settings.es_versions = 1u << LSQVER_I001;
    settings.es_pace_packets = 0;
    memset(&api, 0, sizeof(api));
    api.ea_settings = &settings;
    api.ea_stream_if = &s_server_stream_if;
    api.ea_packets_out = capture_first;
    engine = lsquic_engine_new(LSENG_HTTP, &api);
    if (!engine)
        abort();
    (void) lsquic_engine_connect(engine, LSQVER_I001, (struct sockaddr *) &s_client_sa,
                    (struct sockaddr *) &s_server_sa, NULL, NULL, "localhost", 0,
                    NULL, 0, NULL, 0);
    lsquic_engine_process_conns(engine);
    if (!s_captured)
        abort();                            /* the client always sends an Initial first */
    initial_keys_derive(&keys, s_cl_dcid, s_cl_dcid_len, 1);

    while (end - p >= 2 && n++ < 32)
    {
        unsigned hdr = ((unsigned) p[0] << 8) | p[1];
        size_t len = hdr & 0x3fff, plen;
        p += 2;
        if (len > (size_t) (end - p))
            len = (size_t) (end - p);
        if (hdr & 0x8000)
            (void) lsquic_engine_packet_in(engine, p, len,
                        (struct sockaddr *) &s_client_sa,
                        (struct sockaddr *) &s_server_sa, NULL, 0);
        else
        {
            plen = initial_build(pkt, &keys, 0x00000001, s_cl_scid, s_cl_scid_len,
                                 s_server_cid, sizeof(s_server_cid), NULL, 0, pn++, p, len, 0);
            (void) lsquic_engine_packet_in(engine, pkt, plen,
                        (struct sockaddr *) &s_client_sa,
                        (struct sockaddr *) &s_server_sa, NULL, 0);
        }
        p += len;
        if (hdr & 0x4000)
            lsquic_engine_process_conns(engine);
    }
    lsquic_engine_process_conns(engine);
    lsquic_engine_destroy(engine);
    return 0;
}
