/*
 * libFuzzer harness: QUIC v1 client Initial packets whose *frames* are fuzz data, protected by
 * the harness with the RFC 9001 Initial keys for a fixed DCID, delivered to an lsquic HTTP server
 * engine via lsquic_engine_packet_in(). This gets past packet protection, so the fuzzer drives
 * the IETF mini-connection (CRYPTO/ACK/PING/PADDING/CONNECTION_CLOSE frame handling, delayed
 * packets), the TLS handshake in BoringSSL through lsquic_enc_sess_ietf.c (ClientHello, ALPN,
 * transport-parameter decoding) and promotion to a full connection.
 *
 * Input: repeated  u16 len (big endian) | len bytes  ; each chunk becomes the plaintext payload
 * of one Initial packet (packet numbers 0,1,2...), padded to 1200 bytes. The top 2 bits of len
 * pick a variant: bit 15 sends the datagram twice (duplicate), bit 14 truncates the protected
 * packet to half (a corrupt packet, exercising decrypt failure next to valid ones).
 * A fresh engine per input.
 */
#include "engine_common.h"
#include "quic_initial.h"

static const uint8_t s_dcid[8] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
static const uint8_t s_scid[8] = { 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
static struct initial_keys s_keys;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_global_init();
    fuzz_init_addrs();
    initial_keys_derive(&s_keys, s_dcid, sizeof(s_dcid), 0);
    return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    static uint8_t pkt[0x4000 + 1500];
    struct lsquic_engine_settings settings;
    lsquic_engine_t *engine;
    const uint8_t *p = data, *end = data + size;
    uint32_t pn = 0;

    engine = fuzz_new_server(&settings, LSENG_HTTP);
    if (!engine)
        abort();
    while (end - p >= 2 && pn < 32)
    {
        unsigned hdr = ((unsigned) p[0] << 8) | p[1];
        size_t len = hdr & 0x3fff, plen;
        p += 2;
        if (len > (size_t) (end - p))
            len = (size_t) (end - p);
        plen = initial_build(pkt, &s_keys, 0x00000001, s_dcid, sizeof(s_dcid),
                             s_scid, sizeof(s_scid), NULL, 0, pn++, p, len, 1200);
        p += len;
        if (hdr & 0x4000)
            plen /= 2;
        for (int i = 0; i < ((hdr & 0x8000) ? 2 : 1); ++i)
            (void) lsquic_engine_packet_in(engine, pkt, plen,
                        (struct sockaddr *) &s_server_sa,
                        (struct sockaddr *) &s_client_sa, NULL, 0);
        lsquic_engine_process_conns(engine);
    }
    lsquic_engine_process_conns(engine);
    lsquic_engine_destroy(engine);
    return 0;
}
