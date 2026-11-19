/*
 * Shared setup for the lsquic engine harnesses: a self-signed TLS 1.3 SSL_CTX (generated once,
 * read-only afterwards), callbacks that drain streams, and a server engine built through the
 * public API (lsquic.h). Each harness creates and destroys its engine(s) per input; only the
 * SSL_CTX and lsquic_global_init() state are kept across inputs, and neither is modified by them.
 */
#ifndef FUZZ_ENGINE_COMMON_H
#define FUZZ_ENGINE_COMMON_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bytestring.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "lsquic.h"

static SSL_CTX *s_ssl_ctx;

static const unsigned char s_alpn_list[] = "\x02h3\x0ahq-interop\x05h3-29";

static int
fuzz_select_alpn (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen, void *arg)
{
    (void) ssl; (void) arg;
    if (OPENSSL_NPN_NEGOTIATED == SSL_select_next_proto((unsigned char **) out,
            outlen, in, inlen, s_alpn_list, sizeof(s_alpn_list) - 1))
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *
fuzz_make_ssl_ctx (void)
{
    SSL_CTX *ctx;
    EVP_PKEY *pkey;
    EC_KEY *ec;
    X509 *x;
    X509_NAME *name;

    ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, fuzz_select_alpn, NULL);
    SSL_CTX_set_early_data_enabled(ctx, 1);

    ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600L * 24 * 365 * 50);
    X509_set_pubkey(x, pkey);
    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) "localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_sign(x, pkey, EVP_sha256());
    if (1 != SSL_CTX_use_certificate(ctx, x) || 1 != SSL_CTX_use_PrivateKey(ctx, pkey))
        abort();
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ctx;
}

static SSL_CTX *
fuzz_get_ssl_ctx (void *peer_ctx, const struct sockaddr *local)
{
    (void) peer_ctx; (void) local;
    return s_ssl_ctx;
}

static SSL_CTX *
fuzz_lookup_cert (void *ctx, const struct sockaddr *local, const char *sni)
{
    (void) ctx; (void) local; (void) sni;
    return s_ssl_ctx;
}

/* Datagrams the engine sends are dropped unless a harness installs its own. */
static int
fuzz_drop_packets_out (void *ctx, const struct lsquic_out_spec *specs, unsigned n)
{
    (void) ctx; (void) specs;
    return (int) n;
}

static lsquic_conn_ctx_t *
fuzz_on_new_conn (void *ctx, lsquic_conn_t *c)
{
    (void) ctx; (void) c;
    return NULL;
}

static void
fuzz_on_conn_closed (lsquic_conn_t *c)
{
    (void) c;
}

static lsquic_stream_ctx_t *
fuzz_on_new_stream (void *ctx, lsquic_stream_t *s)
{
    (void) ctx;
    if (s)
        lsquic_stream_wantread(s, 1);
    return NULL;
}

static void
fuzz_on_read (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    unsigned char buf[0x1000];
    ssize_t n;
    (void) h;
    while ((n = lsquic_stream_read(s, buf, sizeof(buf))) > 0)
        ;
    if (n == 0)
    {
        lsquic_stream_wantread(s, 0);
        lsquic_stream_close(s);
    }
    else if (n < 0)
        lsquic_stream_wantread(s, 0);
}

static void
fuzz_on_write (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void) h;
    lsquic_stream_wantwrite(s, 0);
}

static void
fuzz_on_close (lsquic_stream_t *s, lsquic_stream_ctx_t *h)
{
    (void) s; (void) h;
}

static const struct lsquic_stream_if s_server_stream_if = {
    .on_new_conn    = fuzz_on_new_conn,
    .on_conn_closed = fuzz_on_conn_closed,
    .on_new_stream  = fuzz_on_new_stream,
    .on_read        = fuzz_on_read,
    .on_write       = fuzz_on_write,
    .on_close       = fuzz_on_close,
};

static void
fuzz_global_init (void)
{
    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT))
        abort();
    s_ssl_ctx = fuzz_make_ssl_ctx();
}

/* lsquic copies peer/local addresses as sockaddr_in6-sized blobs (lsquic_pr_queue.c,
 * lsquic_engine.c), so, like real callers, hand it sockaddr_storage-backed addresses. */
static struct sockaddr_storage s_server_ss, s_client_ss;
#define s_server_sa (*(struct sockaddr_in *) &s_server_ss)
#define s_client_sa (*(struct sockaddr_in *) &s_client_ss)

static void
fuzz_init_addrs (void)
{
    memset(&s_server_ss, 0, sizeof(s_server_ss));
    memset(&s_client_ss, 0, sizeof(s_client_ss));
    s_server_sa.sin_family = AF_INET;
    s_server_sa.sin_port = htons(443);
    s_server_sa.sin_addr.s_addr = htonl(0x7f000001);
    s_client_sa = s_server_sa;
    s_client_sa.sin_port = htons(50000);
    s_client_sa.sin_addr.s_addr = htonl(0x7f000002);
}

/* A server engine with every supported version enabled, including the deprecated gQUIC ones. */
static lsquic_engine_t *
fuzz_new_server (struct lsquic_engine_settings *settings, unsigned flags)
{
    struct lsquic_engine_api api;

    lsquic_engine_init_settings(settings, LSENG_SERVER | flags);
    settings->es_versions = LSQUIC_SUPPORTED_VERSIONS;
    settings->es_ecn = 1;
    memset(&api, 0, sizeof(api));
    api.ea_settings = settings;
    api.ea_stream_if = &s_server_stream_if;
    api.ea_packets_out = fuzz_drop_packets_out;
    api.ea_get_ssl_ctx = fuzz_get_ssl_ctx;
    api.ea_lookup_cert = fuzz_lookup_cert;
    return lsquic_engine_new(LSENG_SERVER | flags, &api);
}

#endif
