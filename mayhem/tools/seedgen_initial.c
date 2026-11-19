/*
 * Seed generator for fuzz_server_initial (not built by build.sh; run by hand when refreshing
 * seeds). Starts a real lsquic client engine (SCID fixed to the harness's s_scid so the
 * initial_source_connection_id transport parameter matches), captures its first flight, removes
 * the Initial protection and writes the plaintext frames in the harness's input format
 * (u16 len | frames) to the file named by argv[1]. argv[2] = ALPN (default h3).
 *   cc -Iinclude -Imayhem/harnesses -I$BSSL/include mayhem/tools/seedgen_initial.c liblsquic.a \
 *      $BSSL/lib/libssl.a $BSSL/lib/libcrypto.a -lz -lm -lpthread -lstdc++ -o seedgen
 */
#include <stdio.h>
#include "engine_common.h"
#include "quic_initial.h"

static const uint8_t s_scid[8] = { 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
static FILE *s_out;

static void
gen_scid (void *ctx, lsquic_conn_t *c, uint8_t *scid, unsigned len)
{
    (void) ctx; (void) c;
    memcpy(scid, s_scid, len < 8 ? len : 8);
}

static int
capture (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    (void) ctx;
    for (unsigned i = 0; i < n; ++i)
    {
        uint8_t buf[1500];
        size_t len = 0, off, plen;
        struct initial_keys k;
        for (size_t j = 0; j < specs[i].iovlen; ++j)
        {
            memcpy(buf + len, specs[i].iov[j].iov_base, specs[i].iov[j].iov_len);
            len += specs[i].iov[j].iov_len;
        }
        if ((buf[0] & 0xf0) != 0xc0)
            continue;
        initial_keys_derive(&k, buf + 6, buf[5], 0);
        if (0 != initial_open(buf, len, &k, &off, &plen))
        {
            fprintf(stderr, "decrypt failed\n");
            continue;
        }
        while (plen > 0 && buf[off + plen - 1] == 0)
            --plen;                      /* strip PADDING; the harness re-pads */
        fputc((int) (plen >> 8), s_out);
        fputc((int) (plen & 0xff), s_out);
        fwrite(buf + off, 1, plen, s_out);
        fprintf(stderr, "captured %zu plaintext bytes\n", plen);
    }
    return (int) n;
}

int
main (int argc, char **argv)
{
    struct lsquic_engine_settings settings;
    struct lsquic_engine_api api;
    lsquic_engine_t *engine;

    if (argc < 2)
        return 2;
    s_out = fopen(argv[1], "wb");
    fuzz_global_init();
    fuzz_init_addrs();
    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    settings.es_versions = 1u << LSQVER_I001;
    memset(&api, 0, sizeof(api));
    api.ea_settings = &settings;
    api.ea_stream_if = &s_server_stream_if;
    api.ea_packets_out = capture;
    api.ea_generate_scid = gen_scid;
    api.ea_alpn = argc > 2 ? argv[2] : "h3";
    engine = lsquic_engine_new(argc > 2 ? 0 : LSENG_HTTP, &api);
    lsquic_engine_connect(engine, LSQVER_I001, (struct sockaddr *) &s_client_sa,
                          (struct sockaddr *) &s_server_sa, NULL, NULL, "localhost", 0,
                          NULL, 0, NULL, 0);
    lsquic_engine_process_conns(engine);
    lsquic_engine_destroy(engine);
    fclose(s_out);
    return 0;
}
