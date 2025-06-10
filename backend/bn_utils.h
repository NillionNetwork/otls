#ifndef PRIMUS_BN_UTILS_H__
#define PRIMUS_BN_UTILS_H__

#include <openssl/bn.h>
#include "emp-tool/emp-tool.h"
using namespace emp;

extern "C" {
#include <relic/relic.h>
#include <relic/relic_core.h>
#include <relic/relic_types.h>
}


/* Hash the 128-bit block into a large field with a ccrh hasher */
inline void H(BIGNUM* out, block b, BIGNUM* q, BN_CTX* ctx, CCRH& ccrh) {
    block arr[2];
    arr[0] = b ^ makeBlock(0, 1);
    arr[1] = b ^ makeBlock(0, 2);
    ccrh.H<2>(arr, arr);

    BN_bin2bn((unsigned char*)arr, 32, out);
    BN_mod(out, out, q, ctx);
}

/* Send a big integer with IO */
template <typename IO>
inline void send_bn(IO* io, BIGNUM* bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    uint32_t length = BN_bn2bin(bn, arr);
    io->send_data(&length, sizeof(uint32_t));
    io->send_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
}

/* Receive a big integer with IO */
template <typename IO>
inline void recv_bn(IO* io, BIGNUM* bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    uint32_t length = -1;
    io->recv_data(&length, sizeof(uint32_t));
    io->recv_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
    BN_bin2bn(arr, length, bn);
}

/* Send a RELIC big integer with IO */
template <typename IO>
inline void send_bn(IO* io, const bn_t bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    int length = bn_size_bin(bn);
    bn_write_bin(arr, length, bn);
    io->send_data(&length, sizeof(uint32_t));
    io->send_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
}

/* Receive a RELIC big integer with IO */
template <typename IO>
inline void recv_bn(IO* io, bn_t bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    uint32_t length = -1;
    io->recv_data(&length, sizeof(uint32_t));
    io->recv_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
    bn_read_bin(bn, arr, length);
}

/* Garbling an AND gate with half gates*/
inline void garble_gate_garble_halfgates(block LA0,
                                         block A1,
                                         block LB0,
                                         block B1,
                                         block* out0,
                                         block* out1,
                                         block delta,
                                         block* table,
                                         uint64_t idx,
                                         const AES_KEY* key) {
    long pa = getLSB(LA0);
    long pb = getLSB(LB0);
    block tweak1, tweak2;
    block HLA0, HA1, HLB0, HB1;
    block tmp, W0;

    tweak1 = makeBlock(2 * idx, (uint64_t)0);
    tweak2 = makeBlock(2 * idx + 1, (uint64_t)0);

    {
        block masks[4], keys[4];

        keys[0] = sigma(LA0) ^ tweak1;
        keys[1] = sigma(A1) ^ tweak1;
        keys[2] = sigma(LB0) ^ tweak2;
        keys[3] = sigma(B1) ^ tweak2;
        memcpy(masks, keys, sizeof keys);
        AES_ecb_encrypt_blks(keys, 4, key);
        HLA0 = keys[0] ^ masks[0];
        HA1 = keys[1] ^ masks[1];
        HLB0 = keys[2] ^ masks[2];
        HB1 = keys[3] ^ masks[3];
    }

    table[0] = HLA0 ^ HA1;
    table[0] = table[0] ^ (select_mask[pb] & delta);
    W0 = HLA0;
    W0 = W0 ^ (select_mask[pa] & table[0]);
    tmp = HLB0 ^ HB1;
    table[1] = tmp ^ LA0;
    W0 = W0 ^ HLB0;
    W0 = W0 ^ (select_mask[pb] & tmp);

    *out0 = W0;
    *out1 = *out0 ^ delta;
}

/* Check the block is zero */
inline bool isZero(const block* b) { return _mm_testz_si128(*b, *b) > 0; }

/* Check the block is one */
inline bool isOne(const block* b) {
    __m128i neq = _mm_xor_si128(*b, all_one_block);
    return _mm_testz_si128(neq, neq) > 0;
}

/* Evaluating an AND gate with half gates*/
inline void garble_gate_eval_halfgates(
  block A, block B, block* out, const block* table, uint64_t idx, const AES_KEY* key) {
    block HA, HB, W;
    int sa, sb;
    block tweak1, tweak2;

    sa = getLSB(A);
    sb = getLSB(B);

    tweak1 = makeBlock(2 * idx, (long)0);
    tweak2 = makeBlock(2 * idx + 1, (long)0);

    {
        block keys[2];
        block masks[2];

        keys[0] = sigma(A) ^ tweak1;
        keys[1] = sigma(B) ^ tweak2;
        masks[0] = keys[0];
        masks[1] = keys[1];
        AES_ecb_encrypt_blks(keys, 2, key);
        HA = keys[0] ^ masks[0];
        HB = keys[1] ^ masks[1];
    }

    W = HA ^ HB;
    W = W ^ (select_mask[sa] & table[0]);
    W = W ^ (select_mask[sb] & table[1]);
    W = W ^ (select_mask[sb] & A);

    *out = W;
}

/**
 * @brief Converts a RELIC bn_t number to an OpenSSL BIGNUM
 * 
 * This function takes a RELIC big number (bn_t) and converts it to an OpenSSL BIGNUM.
 * The conversion is done by:
 * 1. Getting the binary size of the RELIC number
 * 2. Allocating a buffer to hold the binary representation
 * 3. Writing the RELIC number to the buffer in binary format
 * 4. Converting the binary data to an OpenSSL BIGNUM
 * 
 * @param relic_bn The RELIC bn_t number to convert
 * @return BIGNUM* The converted OpenSSL BIGNUM, or NULL if conversion fails
 * @note The caller is responsible for freeing the returned BIGNUM using BN_free()
 */
inline BIGNUM* relic_bn_to_openssl_bignum(const bn_t relic_bn) {
    int size = bn_size_bin(relic_bn);
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        return NULL;
    }
    bn_write_bin(buffer, size, relic_bn);
    BIGNUM *openssl_bn = BN_bin2bn(buffer, size, NULL);
    free(buffer);
    return openssl_bn;
}

/**
 * @brief Converts a vector of RELIC bn_t numbers to a vector of OpenSSL BIGNUM pointers
 */
inline std::vector<BIGNUM*> relic_bn_vec_to_openssl_bignum_vec(const bn_t* relic_bns, size_t len) {
    std::vector<BIGNUM*> openssl_bns;
    openssl_bns.reserve(len);
    for (size_t i = 0; i < len; i++) {
        openssl_bns.push_back(relic_bn_to_openssl_bignum(relic_bns[i]));
    }
    return openssl_bns;
}

/**
 * @brief Converts an OpenSSL BIGNUM to a RELIC bn_t number
 * 
 * This function takes an OpenSSL BIGNUM and converts it to a RELIC bn_t number.
 * The conversion is done by:
 * 1. Getting the binary size of the OpenSSL BIGNUM
 * 2. Allocating a buffer to hold the binary representation
 * 3. Converting the OpenSSL BIGNUM to binary format
 * 4. Reading the binary data into a RELIC bn_t number
 * 
 * @param relic_bn The RELIC bn_t number to store the result
 * @param openssl_bn The OpenSSL BIGNUM to convert
 * @return int RLC_OK on success, RLC_ERR on failure
 * @note The caller is responsible for initializing and freeing the RELIC bn_t number
 */
inline int openssl_bignum_to_relic_bn(bn_t relic_bn, const BIGNUM *openssl_bn) {
    int size = BN_num_bytes(openssl_bn);
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        return RLC_ERR;
    }
    BN_bn2bin(openssl_bn, buffer);
    bn_read_bin(relic_bn, buffer, size);
    free(buffer);
    return RLC_OK;
}

/**
 * @brief Converts a vector of OpenSSL BIGNUM pointers to RELIC bn_t numbers
 */
inline void openssl_bignum_vec_to_relic_bn_vec(bn_t* relic_bns, const std::vector<BIGNUM*>& openssl_bns) {
    for (size_t i = 0; i < openssl_bns.size(); i++) {
        openssl_bignum_to_relic_bn(relic_bns[i], openssl_bns[i]);
    }
}

#endif // PRIMUS_BN_UTILS_H__
