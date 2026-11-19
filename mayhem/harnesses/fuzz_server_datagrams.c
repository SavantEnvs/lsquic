/*
 * libFuzzer harness: raw UDP datagrams into an lsquic HTTP server engine through the public API
 * (lsquic_engine_packet_in + lsquic_engine_process_conns). Every supported version is enabled
 * (IETF v1/v2/draft-29/ID27 and gQUIC Q043/Q046/Q050), so this reaches packet-header parsing for
 * all versions, version negotiation, stateless reset / retry token code, CID purgatory and
 * mini-connection creation, plus decryption-failure paths.
 *
 * Input: repeated  u16 len (big endian) | len bytes  ; each chunk is one datagram from a fixed
 * client address, delivered with ECN codepoint = (len >> 14) & 3. A fresh engine per input.
 */
#include "engine_common.h"

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
    struct lsquic_engine_settings settings;
    lsquic_engine_t *engine;
    const uint8_t *p = data, *end = data + size;
    unsigned n = 0;

    engine = fuzz_new_server(&settings, LSENG_HTTP);
    if (!engine)
        abort();
    while (end - p >= 2 && n++ < 64)
    {
        unsigned hdr = ((unsigned) p[0] << 8) | p[1];
        size_t len = hdr & 0x3fff;
        p += 2;
        if (len > (size_t) (end - p))
            len = (size_t) (end - p);
        (void) lsquic_engine_packet_in(engine, p, len,
                    (struct sockaddr *) &s_server_sa,
                    (struct sockaddr *) &s_client_sa, NULL, (int) (hdr >> 14));
        p += len;
        lsquic_engine_process_conns(engine);
    }
    lsquic_engine_process_conns(engine);
    lsquic_engine_destroy(engine);
    return 0;
}
