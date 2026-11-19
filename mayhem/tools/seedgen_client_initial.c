/*
 * Seed generator for fuzz_client_initial (not built by build.sh). Runs an lsquic client and an
 * lsquic HTTP server back to back, captures the server's Initial packets of the first flight,
 * removes their protection with the server Initial keys for the client's DCID and writes the
 * plaintext frames (ACK + CRYPTO ServerHello) as "u16 len | frames" records to argv[1].
 * Build like seedgen_initial.c.
 */
#include <stdio.h>
#include "engine_common.h"
#include "quic_initial.h"

static FILE *s_out;
static uint8_t s_dcid[20]; static size_t s_dcid_len;
static uint8_t s_c2s[8][1500]; static size_t s_c2s_len[8]; static unsigned s_n_c2s;
static uint8_t s_s2c[8][1500]; static size_t s_s2c_len[8]; static unsigned s_n_s2c;

static int
cl_out (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    (void) ctx;
    for (unsigned i = 0; i < n && s_n_c2s < 8; ++i)
    {
        size_t len = 0;
        for (size_t j = 0; j < specs[i].iovlen; ++j)
        {
            memcpy(s_c2s[s_n_c2s] + len, specs[i].iov[j].iov_base, specs[i].iov[j].iov_len);
            len += specs[i].iov[j].iov_len;
        }
        if (s_dcid_len == 0)
        {
            s_dcid_len = s_c2s[s_n_c2s][5];
            memcpy(s_dcid, s_c2s[s_n_c2s] + 6, s_dcid_len);
        }
        s_c2s_len[s_n_c2s++] = len;
    }
    return (int) n;
}

static int
sv_out (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    (void) ctx;
    for (unsigned i = 0; i < n && s_n_s2c < 8; ++i)
    {
        size_t len = 0;
        for (size_t j = 0; j < specs[i].iovlen; ++j)
        {
            memcpy(s_s2c[s_n_s2c] + len, specs[i].iov[j].iov_base, specs[i].iov[j].iov_len);
            len += specs[i].iov[j].iov_len;
        }
        s_s2c_len[s_n_s2c++] = len;
    }
    return (int) n;
}

int
main (int argc, char **argv)
{
    struct lsquic_engine_settings cs, ss;
    struct lsquic_engine_api ca, sa;
    lsquic_engine_t *client, *server;
    struct initial_keys k;

    if (argc < 2)
        return 2;
    s_out = fopen(argv[1], "wb");
    fuzz_global_init();
    fuzz_init_addrs();
    lsquic_engine_init_settings(&cs, LSENG_HTTP);
    cs.es_versions = 1u << LSQVER_I001;
    memset(&ca, 0, sizeof(ca));
    ca.ea_settings = &cs; ca.ea_stream_if = &s_server_stream_if; ca.ea_packets_out = cl_out;
    client = lsquic_engine_new(LSENG_HTTP, &ca);
    lsquic_engine_init_settings(&ss, LSENG_HTTP_SERVER);
    ss.es_versions = 1u << LSQVER_I001;
    memset(&sa, 0, sizeof(sa));
    sa.ea_settings = &ss; sa.ea_stream_if = &s_server_stream_if; sa.ea_packets_out = sv_out;
    sa.ea_get_ssl_ctx = fuzz_get_ssl_ctx; sa.ea_lookup_cert = fuzz_lookup_cert;
    server = lsquic_engine_new(LSENG_HTTP_SERVER, &sa);
    lsquic_engine_connect(client, LSQVER_I001, (struct sockaddr *) &s_client_sa,
                          (struct sockaddr *) &s_server_sa, NULL, NULL, "localhost", 0,
                          NULL, 0, NULL, 0);
    lsquic_engine_process_conns(client);
    for (unsigned i = 0; i < s_n_c2s; ++i)
        lsquic_engine_packet_in(server, s_c2s[i], s_c2s_len[i], (struct sockaddr *) &s_server_sa,
                                (struct sockaddr *) &s_client_sa, NULL, 0);
    lsquic_engine_process_conns(server);
    initial_keys_derive(&k, s_dcid, s_dcid_len, 1);
    for (unsigned i = 0; i < s_n_s2c; ++i)
    {
        size_t off, plen;
        uint8_t *b = s_s2c[i];
        if ((b[0] & 0xf0) != 0xc0)
            continue;
        if (0 != initial_open(b, s_s2c_len[i], &k, &off, &plen))
            continue;
        while (plen > 0 && b[off + plen - 1] == 0)
            --plen;
        fputc((int) (plen >> 8), s_out); fputc((int) (plen & 0xff), s_out);
        fwrite(b + off, 1, plen, s_out);
        fprintf(stderr, "captured server Initial: %zu plaintext bytes\n", plen);
    }
    fclose(s_out);
    return 0;
}
