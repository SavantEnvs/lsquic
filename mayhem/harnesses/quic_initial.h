/*
 * RFC 9001 Initial packet protection for QUIC v1, computed by the harness (BoringSSL HKDF,
 * AES-128-GCM, AES-ECB header protection) so fuzz-generated frames reach the server's
 * frame handling instead of being dropped at decryption. This is the same envelope a real
 * client applies; the payload itself is fuzz data.
 */
#ifndef FUZZ_QUIC_INITIAL_H
#define FUZZ_QUIC_INITIAL_H

#include <stdint.h>
#include <string.h>
#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>

static const uint8_t s_v1_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

struct initial_keys { uint8_t key[16], iv[12], hp[16]; };

static void
hkdf_expand_label (uint8_t *out, size_t out_len, const uint8_t *secret,
                   const char *label)
{
    uint8_t info[64];
    size_t llen = strlen(label), n = 0;
    info[n++] = (uint8_t) (out_len >> 8);
    info[n++] = (uint8_t) out_len;
    info[n++] = (uint8_t) (6 + llen);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, llen); n += llen;
    info[n++] = 0;
    HKDF_expand(out, out_len, EVP_sha256(), secret, 32, info, n);
}

/* is_server = 0 -> keys protecting client-to-server Initials. */
static void
initial_keys_derive (struct initial_keys *k, const uint8_t *dcid, size_t dcid_len,
                     int is_server)
{
    uint8_t initial[32], secret[32];
    size_t olen = sizeof(initial);
    HKDF_extract(initial, &olen, EVP_sha256(), dcid, dcid_len, s_v1_salt,
                 sizeof(s_v1_salt));
    hkdf_expand_label(secret, 32, initial, is_server ? "server in" : "client in");
    hkdf_expand_label(k->key, 16, secret, "quic key");
    hkdf_expand_label(k->iv, 12, secret, "quic iv");
    hkdf_expand_label(k->hp, 16, secret, "quic hp");
}

/*
 * Build a protected long-header Initial packet into out (needs payload_len + 128 bytes, or
 * min_size + 64), padding the plaintext with PADDING frames to reach min_size.  Returns length.
 * pn is encoded in 2 bytes.
 */
static size_t
initial_build (uint8_t *out, const struct initial_keys *k, uint32_t version,
               const uint8_t *dcid, size_t dcid_len, const uint8_t *scid, size_t scid_len,
               const uint8_t *token, size_t token_len,
               uint32_t pn, const uint8_t *payload, size_t payload_len, size_t min_size)
{
    size_t n = 0, pn_off, hdr_len, plain_len, length_field;
    uint8_t nonce[12], mask[16];
    AES_KEY hp;
    EVP_AEAD_CTX aead;
    size_t out_len;

    out[n++] = 0xc0 | 0x01;                 /* long header, Initial, 2-byte packet number */
    out[n++] = (uint8_t) (version >> 24); out[n++] = (uint8_t) (version >> 16);
    out[n++] = (uint8_t) (version >> 8);  out[n++] = (uint8_t) version;
    out[n++] = (uint8_t) dcid_len; memcpy(out + n, dcid, dcid_len); n += dcid_len;
    out[n++] = (uint8_t) scid_len; memcpy(out + n, scid, scid_len); n += scid_len;
    /* token length: 2-byte varint */
    out[n++] = 0x40 | (uint8_t) (token_len >> 8); out[n++] = (uint8_t) token_len;
    if (token_len) memcpy(out + n, token, token_len);
    n += token_len;
    plain_len = payload_len;
    if (n + 2 + 2 + plain_len + 16 < min_size)
        plain_len = min_size - (n + 2 + 2 + 16);
    if (plain_len < 4)                      /* header-protection sample needs 4+16 bytes after pn */
        plain_len = 4;
    length_field = 2 + plain_len + 16;
    out[n++] = 0x40 | (uint8_t) (length_field >> 8); out[n++] = (uint8_t) length_field;
    pn_off = n;
    out[n++] = (uint8_t) (pn >> 8); out[n++] = (uint8_t) pn;
    hdr_len = n;
    memcpy(out + n, payload, payload_len);
    memset(out + n + payload_len, 0, plain_len - payload_len);

    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 4; ++i)
        nonce[11 - i] ^= (uint8_t) (pn >> (8 * i));
    EVP_AEAD_CTX_init(&aead, EVP_aead_aes_128_gcm(), k->key, 16, 16, NULL);
    EVP_AEAD_CTX_seal(&aead, out + hdr_len, &out_len, plain_len + 16, nonce, 12,
                      out + hdr_len, plain_len, out, hdr_len);
    EVP_AEAD_CTX_cleanup(&aead);

    AES_set_encrypt_key(k->hp, 128, &hp);
    AES_encrypt(out + pn_off + 4, mask, &hp);
    out[0] ^= mask[0] & 0x0f;
    out[pn_off] ^= mask[1];
    out[pn_off + 1] ^= mask[2];
    return hdr_len + out_len;
}

/* Remove protection from a client Initial in place (used by the seed generator). Returns
 * plaintext payload offset/len via out params; 0 on success. */
static int
initial_open (uint8_t *pkt, size_t len, const struct initial_keys *k,
              size_t *payload_off, size_t *payload_len)
{
    size_t n = 5, dcl, scl, tl, plen, pn_off, pn_len;
    uint8_t mask[16], nonce[12];
    uint32_t pn = 0;
    AES_KEY hp;
    EVP_AEAD_CTX aead;
    size_t out_len;

    dcl = pkt[n]; n += 1 + dcl;
    scl = pkt[n]; n += 1 + scl;
#define VARINT(v) do { unsigned b = pkt[n] >> 6, l = 1u << b; v = pkt[n] & 0x3f; \
        for (unsigned i_ = 1; i_ < l; ++i_) v = (v << 8) | pkt[n + i_]; n += l; } while (0)
    VARINT(tl); n += tl;
    VARINT(plen);
#undef VARINT
    pn_off = n;
    AES_set_encrypt_key(k->hp, 128, &hp);
    AES_encrypt(pkt + pn_off + 4, mask, &hp);
    pkt[0] ^= mask[0] & 0x0f;
    pn_len = (pkt[0] & 3) + 1;
    for (size_t i = 0; i < pn_len; ++i)
    {
        pkt[pn_off + i] ^= mask[1 + i];
        pn = (pn << 8) | pkt[pn_off + i];
    }
    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 4; ++i)
        nonce[11 - i] ^= (uint8_t) (pn >> (8 * i));
    EVP_AEAD_CTX_init(&aead, EVP_aead_aes_128_gcm(), k->key, 16, 16, NULL);
    if (!EVP_AEAD_CTX_open(&aead, pkt + pn_off + pn_len, &out_len, plen - pn_len,
                           nonce, 12, pkt + pn_off + pn_len, plen - pn_len,
                           pkt, pn_off + pn_len))
    {
        EVP_AEAD_CTX_cleanup(&aead);
        return -1;
    }
    EVP_AEAD_CTX_cleanup(&aead);
    (void) len;
    *payload_off = pn_off + pn_len;
    *payload_len = out_len;
    return 0;
}

#endif
