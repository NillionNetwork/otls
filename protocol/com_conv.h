#ifndef PRIMUS_COM_COV_H
#define PRIMUS_COM_COV_H
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <string>
#include <numeric>

#include "backend/bn_utils.h"
#include "backend/ole.h"

extern "C" {
#include <relic/relic.h>
#include <relic/relic_core.h>
#include <relic/relic_types.h>
}

/**
 * @brief Pedersen Commitment scheme using RELIC elliptic curve points.
 *
 * This class implements the Pedersen commitment scheme using RELIC's ep_t and bn_t types.
 * It allows committing to a value and later opening the commitment for verification.
 */
class RelicPedersenComm {
public:
    ec_t h;    ///< Secondary generator point for the commitment
    bn_t order;///< Order of the elliptic curve group
    /**
     * @brief Constructor for the Pedersen commitment scheme.
     * 
     * Initializes the commitment scheme with a given secondary generator point h.
     * Copies h and retrieves the group order.
     * 
     * @param h The secondary generator point (ec_t) to use for the commitment.
     */
    RelicPedersenComm(const ec_t h) {
        // Initialize RELIC types
        ec_null(this->h);
        bn_null(order);
        
        // Allocate memory
        ec_new(this->h);
        bn_new(order);
        
        // Copy the generator point
        ec_copy(this->h, h);
        
        // Get the group order
        ec_curve_get_ord(this->order);
    }

    /**
     * @brief Destructor for the Pedersen commitment scheme.
     * 
     * Frees the memory allocated for the generator point and group order.
     */
    ~RelicPedersenComm() {
        ec_free(h);
        bn_free(order);
    }

    /**
     * @brief Create a Pedersen commitment.
     * 
     * Computes a commitment to the message using a random blinding factor.
     * The commitment is: com = msg*G + rnd*h, where G is the curve generator.
     * 
     * @param[out] com The resulting commitment point (ec_t).
     * @param[out] rnd The random blinding factor used (bn_t).
     * @param[in]  msg The message to commit to (bn_t).
     */
    inline void commit(ec_t com, bn_t rnd, const bn_t msg) {
        // Initialize
        ec_t msg_G;
        ec_null(msg_G);
        ec_new(msg_G);
        
        // Generate random number in [0, order-1]
        bn_rand_mod(rnd, order);
        
        // Compute commitment: com = msg*G + rnd*h
        ec_mul(com, h, rnd);        // com = rnd*h
        ec_mul_gen(msg_G, msg);     // msg_G = msg*G
        ec_add(com, msg_G, com);    // com = msg_G + com

        // Clean up
        ec_free(msg_G);
    }

    /**
     * @brief Verify a Pedersen commitment.
     * 
     * Checks if the provided commitment corresponds to the given message and blinding factor.
     * 
     * @param[in] com The commitment point to verify (ec_t).
     * @param[in] rnd The blinding factor used in the commitment (bn_t).
     * @param[in] msg The original message (bn_t).
     * @return true if the commitment is valid, false otherwise.
     */
    inline bool open_check(const ec_t com, const bn_t rnd, const bn_t msg) {
        // Initialize
        ec_t expected_com;
        ec_t msg_G;
        ec_null(expected_com);
        ec_null(msg_G);
        ec_new(expected_com);
        ec_new(msg_G);
        
        // Compute expected commitment
        ec_mul(expected_com, h, rnd);      // expected_com = rnd*h
        ec_mul_gen(msg_G, msg);            // msg_G = msg*G
        ec_add(expected_com, msg_G, expected_com); // expected_com = msg_G + expected_com
        
        // Compare points
        bool res = (ec_cmp(com, expected_com) == RLC_EQ);
        
        // Clean up
        ec_free(expected_com);
        ec_free(msg_G);
        return res;
    }

    /**
     * @brief Computes the linear combination of commitments and coefficients using RELIC types.
     * 
     * res = sum_{i=0}^{len-1} coef[i] * coms[i]
     * 
     * @param res   Output: result as a RELIC ec_t (must be initialized)
     * @param coms  Array of RELIC ec_t commitment points
     * @param coef  Array of RELIC bn_t coefficients
     * @param len   Number of elements in the arrays
     */
    inline void linear_comb_com(ec_t res, const ec_t* coms, const bn_t* coef, size_t len) {
        ec_t tmp;
        ec_null(tmp);
        ec_new(tmp);
        
        // Initialize result to point at infinity
        ec_set_infty(res);
        
        for (size_t i = 0; i < len; i++) {
            // tmp = coef[i] * coms[i]
            ec_mul(tmp, coms[i], coef[i]);
            // res = res + tmp
            ec_add(res, res, tmp);
        }
        
        ec_free(tmp);
    }

    /**
     * @brief Computes the linear combination of randomness and coefficients using RELIC types and arrays.
     * 
     * res = sum_{i=0}^{len-1} rnds[i] * coef[i] mod group order
     * 
     * @param res   Output: result as a RELIC bn_t (must be initialized)
     * @param rnds  Array of RELIC bn_t randomness values
     * @param coef  Array of RELIC bn_t coefficients
     * @param len   Number of elements in the arrays
     */
    inline void linear_comb_rand(bn_t res, const bn_t* rnds, const bn_t* coef, size_t len) {
        bn_t tmp, ord;
        bn_null(tmp); bn_null(ord);
        bn_new(tmp);  bn_new(ord);

        // Get the group order
        ec_curve_get_ord(ord);

        bn_zero(res);
        for (size_t i = 0; i < len; i++) {
            bn_mul(tmp, rnds[i], coef[i]);      // tmp = rnds[i] * coef[i]
            bn_mod(tmp, tmp, ord);              // tmp = tmp mod ord
            bn_add(res, res, tmp);              // res += tmp
            bn_mod(res, res, ord);              // res = res mod ord
        }

        bn_free(tmp);
        bn_free(ord);
    }
};

/* Define the Pederson commitment */
class PedersenComm {
   public:
    EC_GROUP* group = nullptr;
    EC_POINT* h;
    BN_CTX* ctx;

    // h should be chosen very carefully, without any trapdoor.
    PedersenComm(EC_POINT* h, EC_GROUP* group) {
        ctx = BN_CTX_new();
        this->group = group;
        this->h = EC_POINT_new(group);
        EC_POINT_copy(this->h, h);
    }

    ~PedersenComm() {
        EC_POINT_free(h);
        BN_CTX_free(ctx);
    }

    inline void commit(EC_POINT* com, BIGNUM* rnd, const BIGNUM* msg) {
        BN_rand_range(rnd, EC_GROUP_get0_order(group));
        EC_POINT_mul(group, com, msg, h, rnd, ctx);
    }

    inline bool open_check(const EC_POINT* com, const BIGNUM* rnd, const BIGNUM* msg) {
        EC_POINT* expected_com = EC_POINT_new(group);
        EC_POINT_mul(group, expected_com, msg, h, rnd, ctx);
        bool res = (EC_POINT_cmp(group, com, expected_com, ctx) == 0);
        EC_POINT_free(expected_com);

        return res;
    }

    inline void linear_comb_com(EC_POINT* res,
                                const vector<EC_POINT*>& coms,
                                const vector<BIGNUM*>& coef) {
        assert(coms.size() == coef.size());
        EC_POINT_set_to_infinity(group, res);
        EC_POINT* tmp = EC_POINT_new(group);
        for (size_t i = 0; i < coef.size(); i++) {
            EC_POINT_mul(group, tmp, NULL, coms[i], coef[i], ctx);
            EC_POINT_add(group, res, res, tmp, ctx);
        }

        EC_POINT_free(tmp);
    }

    inline void linear_comb_rand(BIGNUM* res,
                                 const vector<BIGNUM*>& rnds,
                                 const vector<BIGNUM*>& coef) {
        assert(rnds.size() == coef.size());
        BIGNUM* tmp = BN_new();
        BN_set_word(res, 0);
        for (size_t i = 0; i < coef.size(); i++) {
            BN_mod_mul(tmp, rnds[i], coef[i], EC_GROUP_get0_order(group), ctx);
            BN_mod_add(res, res, tmp, EC_GROUP_get0_order(group), ctx);
        }

        BN_free(tmp);
    }
};

/* Convert IT-MACed messages into Pedersen commitment */
template <typename IO>
class ComConv {
   public:
    IO* io;
    block bDelta = zero_block;
    BIGNUM* aDelta = nullptr;
    CCRH ccrh;
    unsigned char com[Hash::DIGEST_SIZE];
    unsigned char msg_com[Hash::DIGEST_SIZE];
    Hash chi_hash;
    // q is the order of the ECC group.
    BIGNUM* q;
    BN_CTX* ctx;
    BIGNUM* r = nullptr;
    block com_seed;
    OLE<IO>* ole;
    vector<BIGNUM*> exp;
    
    // Signature storage members
    vector<unsigned char*> signatures_der;
    vector<int> signature_lengths;
    bool signatures_valid = false;

    // Legacy public key storage (used by verify function)
    unsigned char* public_key_bytes = nullptr;
    int public_key_len = 0;

    ComConv(IO* io, COT<IO>* ot, BIGNUM* q2, block bDelta) : io(io) {
        q = BN_new();
        BN_copy(this->q, q2);
        ctx = BN_CTX_new();
        ole = new OLE<IO>(io, ot, q2, BN_num_bits(q2));

        exp.resize(BN_num_bits(q2));
        for (int i = 0; i < BN_num_bits(q2); ++i) {
            exp[i] = BN_new();
            BN_set_bit(exp[i], i);
            BN_mod(exp[i], exp[i], q, ctx);
        }
        this->bDelta = bDelta;
    }
    ~ComConv() {
        if (aDelta != nullptr)
            BN_free(aDelta);
        if (r != nullptr)
            BN_free(r);
        BN_CTX_free(ctx);

        for (int i = 0; i < BN_num_bits(q); ++i)
            BN_free(exp[i]);
        BN_free(q);
        delete ole;
        
        // // Clean up signature data
        // for (auto sig_der : signatures_der) {
        //     OPENSSL_free(sig_der);
        // }
        // signatures_der.clear();
        // signature_lengths.clear();
        
        // if (public_key_bytes != nullptr) {
        //     OPENSSL_free(public_key_bytes);
        //     public_key_bytes = nullptr;
        // }
    }

    void compute_hash(unsigned char res[Hash::DIGEST_SIZE],
                      block seed,
                      block bDelta,
                      BIGNUM* aDelta) {
        Hash hash;
        hash.put(&seed, sizeof(block));
        hash.put(&bDelta, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(aDelta, arr);
        hash.put(&length, sizeof(int));
        hash.put(arr, length);
        hash.digest(res);
    }

    void commitDelta(BIGNUM* aDelta = nullptr) {
        if (aDelta != nullptr) {
            PRG prg;
            prg.random_data(&com_seed, sizeof(block));
            compute_hash(com, com_seed, bDelta, aDelta);
            io->send_data(com, Hash::DIGEST_SIZE);
            this->aDelta = BN_new();
            BN_copy(this->aDelta, aDelta);
            chi_hash.put(com, Hash::DIGEST_SIZE);
        } else {
            io->recv_data(com, Hash::DIGEST_SIZE);
            chi_hash.put(com, Hash::DIGEST_SIZE);
        }
    }

    void convert_recv(vector<BIGNUM*>& aMACs, vector<block>& bMACs) {
        Hash hash;
        vector<BIGNUM*> msg;
        msg.resize(bMACs.size());
        for (size_t i = 0; i < bMACs.size(); ++i) {
            msg[i] = BN_new();
            recv_bn(io, msg[i], &hash);
        }
        hash.digest(msg_com);
        chi_hash.put(msg_com, Hash::DIGEST_SIZE);

        for (size_t i = 0; i < bMACs.size(); ++i) {
            H(aMACs[i], bMACs[i], q, ctx, ccrh);
            if (getLSB(bMACs[i])) {
                BN_sub(aMACs[i], msg[i], aMACs[i]);
                BN_mod_add(aMACs[i], aMACs[i], q, q, ctx);
            }
        }
        for (size_t i = 0; i < bMACs.size(); ++i)
            BN_free(msg[i]);
    }

    void convert_send(vector<BIGNUM*>& aKEYs, vector<block>& bKEYs) {
        Hash hash;
        vector<BIGNUM*> msg;
        msg.resize(bKEYs.size());
        for (size_t i = 0; i < bKEYs.size(); ++i)
            msg[i] = BN_new();
        // Step 3(a) from paper
        convert(msg, aKEYs, bKEYs, bDelta, aDelta);
        for (size_t i = 0; i < msg.size(); ++i)
            // msg[i] is W[i] from paper
            send_bn(io, msg[i], &hash);

        hash.digest(msg_com);
        chi_hash.put(msg_com, Hash::DIGEST_SIZE);

        for (size_t i = 0; i < bKEYs.size(); ++i)
            BN_free(msg[i]);
    }

    void convert(vector<BIGNUM*>& msg,
                 vector<BIGNUM*>& aKEYs,
                 vector<block>& bKEYs,
                 block local_bDelta,
                 BIGNUM* local_aDelta) {
        assert(aKEYs.size() == bKEYs.size());
        for (size_t i = 0; i < aKEYs.size(); ++i) {
            H(aKEYs[i], bKEYs[i], q, ctx, ccrh);
            H(msg[i], bKEYs[i] ^ local_bDelta, q, ctx, ccrh);
            BN_add(msg[i], msg[i], aKEYs[i]);
            BN_mod_add(msg[i], msg[i], local_aDelta, q, ctx);
        }
    }

    void open() {
        io->send_data(&com_seed, sizeof(block));
        io->send_data(&bDelta, sizeof(block));
        send_bn(io, aDelta);
    }
    bool open(vector<block>& bMACs) {
        bool ret = true;
        block tmp_seed, tmp_bDelta;
        BIGNUM* tmp_aDelta = BN_new();
        io->recv_data(&tmp_seed, sizeof(block));
        io->recv_data(&tmp_bDelta, sizeof(block));
        recv_bn(io, tmp_aDelta);
        unsigned char tmp_com[Hash::DIGEST_SIZE];
        compute_hash(tmp_com, tmp_seed, tmp_bDelta, tmp_aDelta);
        ret = ret and (std::strncmp((char*)tmp_com, (char*)com, Hash::DIGEST_SIZE) == 0);

        vector<BIGNUM*> msg;
        msg.resize(bMACs.size());
        vector<BIGNUM*> tmp_akeys;
        tmp_akeys.resize(bMACs.size());
        vector<block> tmp_bkeys(bMACs);
        for (size_t i = 0; i < bMACs.size(); ++i) {
            tmp_akeys[i] = BN_new();
            msg[i] = BN_new();
            if (getLSB(tmp_bkeys[i]))
                tmp_bkeys[i] = tmp_bkeys[i] ^ tmp_bDelta;
        }
        convert(msg, tmp_akeys, tmp_bkeys, tmp_bDelta, tmp_aDelta);
        Hash hash;
        unsigned char arr[1000];
        for (size_t i = 0; i < bMACs.size(); ++i) {
            uint32_t length = BN_bn2bin(msg[i], arr);
            hash.put(arr, length);
        }
        hash.digest(tmp_com);

        BN_free(tmp_aDelta);
        for (size_t i = 0; i < bMACs.size(); ++i) {
            BN_free(tmp_akeys[i]);
            BN_free(msg[i]);
        }

        ret = ret and (std::strncmp((char*)tmp_com, (char*)msg_com, Hash::DIGEST_SIZE) == 0);
        return ret;
    }

    inline void mask_mac(BIGNUM* rMAC) {
        this->r = BN_new();
        BN_rand_range(this->r, q);
        vector<BIGNUM*> out, in;
        out.push_back(rMAC);
        in.push_back(this->r);
        ole->compute(out, in);
    }

    inline void mask_key(BIGNUM* rKEY) {
        vector<BIGNUM*> out, in;
        out.push_back(rKEY);
        in.push_back(this->aDelta);
        ole->compute(out, in);
        BN_sub(rKEY, q, rKEY);
    }

    inline void gen_chi(vector<BIGNUM*>& chi, block seed) {
        PRG prg(&seed);
        unsigned char tmp[BN_num_bytes(q)];
        for (size_t i = 0; i < chi.size(); i++) {
            prg.random_data(tmp, BN_num_bytes(q));
            BN_bin2bn(tmp, BN_num_bytes(q), chi[i]);
            BN_mod(chi[i], chi[i], q, ctx);
        }
    }

    bool compute_com_send(ec_t* com,
                          vector<block> bKEYs,
                          RelicPedersenComm& pc,
                          uint64_t batch_size) {
        BIGNUM* bs_int = BN_new();
        BIGNUM* ONE = BN_new();

        BN_set_bit(bs_int, batch_size);
        BN_set_word(ONE, 1);
        // 2^{bs} - 1
        BN_sub(bs_int, bs_int, ONE);
        int check = BN_cmp(bs_int, q);
        if (check != -1)
            error("batch size is too large!\n");

        BN_free(bs_int);
        BN_free(ONE);
        bool res = true;
        // choose random arithmetic Delta (aDelta), commit bDelta and aDelta.
        BIGNUM* Delta = BN_new();
        BN_rand_range(Delta, this->q);
        commitDelta(Delta);
        BN_free(Delta);

        // generate IT-MAC key for random r;
        BIGNUM* rKEY = BN_new();
        mask_key(rKEY);

        // convert boolean IT-MAC key to arithmetic IT-MAC key.
        vector<BIGNUM*> aKEYs(bKEYs.size());
        for (size_t i = 0; i < aKEYs.size(); i++) {
            aKEYs[i] = BN_new();
        }
        // Step 3(a) from paper
        convert_send(aKEYs, bKEYs);
        //  separate input bits into chunks with batch_size bits each.
        size_t chunk_len = (bKEYs.size() + batch_size - 1) / batch_size;
        BIGNUM* tmp = BN_new();
        vector<BIGNUM*> batch_aKEYs(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            batch_aKEYs[i] = BN_new();
            BN_set_word(batch_aKEYs[i], 0);
        }

        for (size_t i = 0; i < chunk_len; i++) {
            for (size_t j = 0; (j < batch_size) && (i * batch_size + j < bKEYs.size()); j++) {
                BN_mod_mul(tmp, exp[j], aKEYs[i * batch_size + j], q, ctx);
                BN_mod_add(batch_aKEYs[i], batch_aKEYs[i], tmp, q, ctx);
            }
        }
        BN_free(tmp);

        // // receive commitments of chunks from Pb.
        // // could use compressed point.
        // unsigned char* buf = new unsigned char[65];
        // for (size_t i = 0; i < chunk_len; i++) {
        //     io->recv_data(buf, 65);
        //     chi_hash.put(buf, 65);
        //     EC_POINT_oct2point(pc.group, com[i], buf, 65, ctx);
        // }


        int compressed_size = ec_size_bin(com[0], 1);  // 1 for compressed format
        unsigned char* buf = (unsigned char*)malloc(compressed_size);  // RELIC points are 65 bytes uncompressed
        for (size_t i = 0; i < chunk_len; i++) {
            io->recv_data(buf, compressed_size);
            chi_hash.put(buf, compressed_size);
            ec_read_bin(com[i], buf, compressed_size);
        }

        // // receive commitment of r.
        // EC_POINT* comm_r = EC_POINT_new(pc.group);
        // io->recv_data(buf, 65);
        // chi_hash.put(buf, 65);
        // EC_POINT_oct2point(pc.group, comm_r, buf, 65, ctx);
        // delete[] buf;
        ec_t relic_comm_r;
        io->recv_data(buf, compressed_size);
        chi_hash.put(buf, compressed_size);
        ec_read_bin(relic_comm_r, buf, compressed_size);
        delete[] buf;

        // generate and send chi's.
        vector<BIGNUM*> chi(chunk_len);
        for (size_t i = 0; i < chunk_len; i++)
            chi[i] = BN_new();

        unsigned char chi_digest[Hash::DIGEST_SIZE];
        chi_hash.digest(chi_digest);
        block seed = zero_block;
        memcpy(&seed, chi_digest, sizeof(block));
        gen_chi(chi, seed);

        // generate linear combination of IT-MAC keys.
        BIGNUM* yKEY = rKEY;
        BIGNUM* tmpm = BN_new();
        for (size_t i = 0; i < chunk_len; i++) {
            BN_mod_mul(tmpm, chi[i], batch_aKEYs[i], q, ctx);
            BN_mod_add(yKEY, yKEY, tmpm, q, ctx);
        }
        BN_free(tmpm);

        // // generate com_y
        // vector<EC_POINT*> comms(com);
        // comms.push_back(comm_r);
        ec_t relic_comms[chunk_len + 1];
        // Initialize all points
        for (size_t i = 0; i < chunk_len; i++) {
            ec_null(relic_comms[i]);
            ec_new(relic_comms[i]);
            ec_copy(relic_comms[i], com[i]);  // Copy existing commitments
        }
        // Initialize and copy the last point (relic_comm_r)
        ec_null(relic_comms[chunk_len]);
        ec_new(relic_comms[chunk_len]);
        ec_copy(relic_comms[chunk_len], relic_comm_r);

        vector<BIGNUM*> scales(chi);
        BIGNUM* one = BN_new();
        BN_set_word(one, 1);
        scales.push_back(one);
        // convert openssl bignum vectors to relic bn vectors
        bn_t relic_scales[scales.size()];
        for (size_t i = 0; i < scales.size(); i++) {    // Initialize and convert
            bn_null(relic_scales[i]);
            bn_new(relic_scales[i]);
            openssl_bignum_to_relic_bn(relic_scales[i], scales[i]);
        }

        // EC_POINT* com_y = EC_POINT_new(pc.group);
        ec_t relic_com_y;
        ec_null(relic_com_y);
        ec_new(relic_com_y);
        // pc.linear_comb_com(com_y, comms, scales);
        pc.linear_comb_com(relic_com_y, relic_comms, relic_scales, scales.size());

        // receive yMAC_com
        unsigned char yMAC_com[Hash::DIGEST_SIZE];
        io->recv_data(yMAC_com, Hash::DIGEST_SIZE);

        // // receive opening of com_y;
        // BIGNUM* rnd_y = BN_new();
        // BIGNUM* msg_y = BN_new();
        // recv_bn(io, rnd_y);
        // recv_bn(io, msg_y);
        bn_t relic_rnd_y, relic_msg_y;
        bn_null(relic_rnd_y); bn_null(relic_msg_y);
        bn_new(relic_rnd_y); bn_new(relic_msg_y);
        recv_bn(io, relic_rnd_y);
        recv_bn(io, relic_msg_y);

        res = res and pc.open_check(relic_com_y, relic_rnd_y, relic_msg_y);

        open();

        // check open of com_y
        block yMAC_seed = zero_block;
        io->recv_block(&yMAC_seed, 1);
        BIGNUM* yMAC = BN_new();
        recv_bn(io, yMAC);

        unsigned char yMAC_com_comp[Hash::DIGEST_SIZE];
        Hash hash;
        hash.put(&yMAC_seed, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(yMAC, arr);
        hash.put(arr, length);
        hash.digest(yMAC_com_comp);

        res = res and (memcmp(yMAC_com, yMAC_com_comp, Hash::DIGEST_SIZE) == 0);

        // check M[y] = K[y] + y* aDelta
        BIGNUM* msg_y = relic_bn_to_openssl_bignum(relic_msg_y);
        BN_mod_mul(msg_y, msg_y, aDelta, q, ctx);
        BN_mod_add(yKEY, yKEY, msg_y, q, ctx);

        res = res and (BN_cmp(yMAC, yKEY) == 0);

        // Sign all commitments individually:
        bool signature_success = sign_commitments_with_ecdsa(com, chunk_len, "private_key.pem");
        if (signature_success) {
            cout << "Created signatures: " << get_signature_info() << endl;
        }

        res = res and signature_success;

        BN_free(yMAC);
        ec_free(relic_com_y);
        for (size_t i = 0; i < chunk_len; i++) {
            BN_free(batch_aKEYs[i]);
            BN_free(chi[i]);
        }
        bn_free(relic_rnd_y);
        bn_free(relic_msg_y);
        BN_free(one);
        BN_free(rKEY);
        for (size_t i = 0; i < aKEYs.size(); i++) {
            BN_free(aKEYs[i]);
        }

        // Clean up when done
        for (size_t i = 0; i < chunk_len + 1; i++) {
            ec_free(relic_comms[i]);
        }

        return res;
    }

    bool compute_com_recv(ec_t* com,
                          vector<BIGNUM*>& rnds,
                          vector<block> bMACs,
                          RelicPedersenComm& pc,
                          uint64_t batch_size) {
        BIGNUM* bs_int = BN_new();
        BIGNUM* ONE = BN_new();

        BN_set_bit(bs_int, batch_size);
        BN_set_word(ONE, 1);
        // 2^{bs} - 1
        BN_sub(bs_int, bs_int, ONE);
        int check = BN_cmp(bs_int, q);
        if (check != -1)
            error("batch size is too large!\n");

        BN_free(bs_int);
        BN_free(ONE);
        bool res = true;
        // receive commitment of bDelta and aDelta.
        commitDelta();

        // generate IT-MAC mac for random r;
        BIGNUM* rMAC = BN_new();
        mask_mac(rMAC);

        // convert boolean IT-MAC mac to arithmetic IT-MAC mac.
        vector<BIGNUM*> aMACs(bMACs.size());
        for (size_t i = 0; i < aMACs.size(); i++) {
            aMACs[i] = BN_new();
        }
        // Step 3(b) from paper
        convert_recv(aMACs, bMACs);
        //  separate input bits into chunks with batch_size bits each.
        size_t chunk_len = (bMACs.size() + batch_size - 1) / batch_size;

        // compute commitment and randomness of chunks.
        vector<BIGNUM*> msg(chunk_len);
        vector<BIGNUM*> batch_aMACs(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            batch_aMACs[i] = BN_new();
            msg[i] = BN_new();
            BN_set_word(batch_aMACs[i], 0);
            BN_set_word(msg[i], 0);
        }

        BIGNUM* tmp = BN_new();
        for (size_t i = 0; i < chunk_len; i++) {
            for (size_t j = 0; (j < batch_size) && (i * batch_size + j < bMACs.size()); j++) {
                if (getLSB(bMACs[i * batch_size + j]))
                    BN_mod_add(msg[i], msg[i], exp[j], q, ctx);

                BN_mod_mul(tmp, exp[j], aMACs[i * batch_size + j], q, ctx);
                BN_mod_add(batch_aMACs[i], batch_aMACs[i], tmp, q, ctx);
            }
            // convert BIGNUM to bn_t
            bn_t relic_rnd, relic_msg;
            bn_null(relic_rnd); bn_new(relic_rnd);
            bn_null(relic_msg); bn_new(relic_msg);

            openssl_bignum_to_relic_bn(relic_rnd, rnds[i]);
            openssl_bignum_to_relic_bn(relic_msg, msg[i]);
            pc.commit(com[i], relic_rnd, relic_msg);
            rnds[i] = relic_bn_to_openssl_bignum(relic_rnd);

            bn_free(relic_rnd);
            bn_free(relic_msg);
        }

        BN_free(tmp);

        // compute commitment and randomness of r.
        // EC_POINT* comm_r = EC_POINT_new(pc.group);
        // BIGNUM* rnd_r = BN_new();
        // pc.commit(comm_r, rnd_r, this->r);
        ec_t relic_comm_r;
        ec_null(relic_comm_r);
        ec_new(relic_comm_r);

        bn_t relic_rnd_r;
        bn_null(relic_rnd_r);
        bn_new(relic_rnd_r);

        bn_t relic_msg_r;
        bn_null(relic_msg_r);
        bn_new(relic_msg_r);

        openssl_bignum_to_relic_bn(relic_msg_r, this->r);
        
        pc.commit(relic_comm_r, relic_rnd_r, relic_msg_r);


        // send commitments of chunks to Pa.
        // could use compressed point.
        // unsigned char* buf = new unsigned char[65];
        // for (size_t i = 0; i < chunk_len; i++) {
        //     EC_POINT_point2oct(pc.group, com[i], POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        //     io->send_data(buf, 65);
        //     chi_hash.put(buf, 65);
        // }
        int compressed_size = ec_size_bin(relic_comm_r, 1);  // 1 for compressed format
        // unsigned char* buf = new unsigned char[compressed_size];  
        unsigned char* buf = (unsigned char*)malloc(compressed_size); 
        for (size_t i = 0; i < chunk_len; i++) {
            ec_write_bin(buf, compressed_size, com[i], 1);  // 1 for compressed format
            io->send_data(buf, compressed_size);
            chi_hash.put(buf, compressed_size);
        }

        // // send commitment of r.
        // EC_POINT_point2oct(pc.group, comm_r, POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        // io->send_data(buf, 65);
        // chi_hash.put(buf, 65);
        ec_write_bin(buf, compressed_size, relic_comm_r, 1);
        io->send_data(buf, compressed_size);
        chi_hash.put(buf, compressed_size);
        
        delete[] buf;

        // receive chi's.
        vector<BIGNUM*> chi(chunk_len);
        for (size_t i = 0; i < chunk_len; i++)
            chi[i] = BN_new();

        unsigned char chi_digest[Hash::DIGEST_SIZE];
        chi_hash.digest(chi_digest);
        block seed = zero_block;
        memcpy(&seed, chi_digest, sizeof(block));

        gen_chi(chi, seed);

        // generate linear combination of IT-MAC macs.
        BIGNUM* yMAC = rMAC;
        BIGNUM* tmpm = BN_new();
        for (size_t i = 0; i < chunk_len; i++) {
            BN_mod_mul(tmpm, chi[i], batch_aMACs[i], q, ctx);
            BN_mod_add(yMAC, yMAC, tmpm, q, ctx);
        }
        BN_free(tmpm);

        // compute linear combination of randomness and message.
        vector<BIGNUM*> scales(chi);
        vector<BIGNUM*> crnds(rnds);
        vector<BIGNUM*> msgs(msg);
        // BIGNUM* rnd_r = BN_new();
        BIGNUM* rnd_r = relic_bn_to_openssl_bignum(relic_rnd_r);
        crnds.push_back(rnd_r);
        msgs.push_back(this->r);
        BIGNUM* one = BN_new();
        BN_set_word(one, 1);
        scales.push_back(one);

        // convert openssl bignum vectors to relic bn vectors
        bn_t relic_scales[scales.size()];
        for (size_t i = 0; i < scales.size(); i++) {    // Initialize and convert
            bn_null(relic_scales[i]);
            bn_new(relic_scales[i]);
            openssl_bignum_to_relic_bn(relic_scales[i], scales[i]);
        }
        bn_t relic_crnds[crnds.size()];
        for (size_t i = 0; i < crnds.size(); i++) {    // Initialize and convert
            bn_null(relic_crnds[i]);
            bn_new(relic_crnds[i]);
            openssl_bignum_to_relic_bn(relic_crnds[i], crnds[i]);
        }
        bn_t relic_msgs[msgs.size()];
        for (size_t i = 0; i < msgs.size(); i++) {    // Initialize and convert
            bn_null(relic_msgs[i]);
            bn_new(relic_msgs[i]);
            openssl_bignum_to_relic_bn(relic_msgs[i], msgs[i]);
        }
        
        // BIGNUM* rnd_y = BN_new();
        // BIGNUM* msg_y = BN_new();
        // pc.linear_comb_rand(rnd_y, crnds, scales);
        // pc.linear_comb_rand(msg_y, msgs, scales);
        bn_t relic_rnd_y, relic_msg_y;
        bn_null(relic_rnd_y); bn_null(relic_msg_y);
        bn_new(relic_rnd_y); bn_new(relic_msg_y);
        pc.linear_comb_rand(relic_rnd_y, relic_crnds, relic_scales, crnds.size());
        pc.linear_comb_rand(relic_msg_y, relic_msgs, relic_scales, msgs.size());
        
        // commit yMAC
        unsigned char yMAC_com[Hash::DIGEST_SIZE];
        PRG prg;
        block yMAC_seed = zero_block;
        prg.random_block(&yMAC_seed);
        Hash hash;
        hash.put(&yMAC_seed, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(yMAC, arr);
        hash.put(arr, length);
        hash.digest(yMAC_com);

        // send the commitment of yMAC
        io->send_data(yMAC_com, Hash::DIGEST_SIZE);
        // // send the open of com_y (randomness and messages);
        // send_bn(io, rnd_y);
        // send_bn(io, msg_y);
        send_bn(io, relic_rnd_y);
        send_bn(io, relic_msg_y);

        res = res and open(bMACs);

        io->send_block(&yMAC_seed, 1);
        send_bn(io, yMAC);


        // Verify signatures
        bool verified = verify_commitment_signature(com, chunk_len, "public_key.pem");
        if (verified) {
            cout << "Verified signatures: " << get_signature_info() << endl;
        }
        res = res and verified;

        res = res and verified;

        res = res and verified;

        res = res and verified;

        res = res and verified;

        res = res and verified;

        res = res and verified;

        res = res and verified;

        for (size_t i = 0; i < chunk_len; i++) {
            BN_free(batch_aMACs[i]);
            BN_free(chi[i]);
            BN_free(msg[i]);
        }

        bn_free(relic_rnd_y);
        bn_free(relic_msg_y);
        BN_free(one);
        bn_free(relic_rnd_r);
        bn_free(relic_msg_r);
        ec_free(relic_comm_r);

        BN_free(rMAC);
        for (size_t i = 0; i < aMACs.size(); i++) {
            BN_free(aMACs[i]);
        }

        return res;
    }

    /**
     * Signs each commitment individually using a predefined ECDSA key
     * and sends the signatures to the other party.
     * 
     * @param com Commitment points to sign
     * @param chunk_len Length of the commitment vector
     * @param key_path Path to the PEM file containing private key
     * @return true if signing succeeds, false otherwise
     */
    bool sign_commitments_with_ecdsa(
        const ec_t* com, 
        size_t chunk_len,
        const string& key_path
    ) {
        // Clean up any previous signature data
        for (auto sig_der : signatures_der) {
            OPENSSL_free(sig_der);
        }
        signatures_der.clear();
        signature_lengths.clear();
        signatures_valid = false;

        // 1. Load the private key
        EC_KEY* ecdsa_key = nullptr;
        FILE* key_file = fopen(key_path.c_str(), "r");
        if (!key_file) {
            fprintf(stderr, "Error: Could not open ECDSA key file at %s\n", key_path.c_str());
            return false;
        }

        ecdsa_key = PEM_read_ECPrivateKey(key_file, nullptr, nullptr, nullptr);
        fclose(key_file);

        if (!ecdsa_key) {
            fprintf(stderr, "Error: Invalid ECDSA key format\n");
            return false;
        }

        // 2. Sign each commitment individually
        for (size_t i = 0; i < chunk_len; i++) {
            // Convert commitment point to binary format
            int compressed_size = ec_size_bin(com[0], 1);
            unsigned char point_buffer[compressed_size];
            ec_write_bin(point_buffer, compressed_size, com[i], 1);

            // Hash the individual commitment
            Hash commitment_hash;
            commitment_hash.put(point_buffer, compressed_size);
            unsigned char digest[Hash::DIGEST_SIZE];
            commitment_hash.digest(digest);

            // Sign the digest
            ECDSA_SIG* signature = ECDSA_do_sign(digest, Hash::DIGEST_SIZE, ecdsa_key);
            if (!signature) {
                fprintf(stderr, "Error: ECDSA signing failed for commitment %zu\n", i);
                EC_KEY_free(ecdsa_key);
                
                // Clean up any signatures we've created so far
                for (auto sig_der : signatures_der) {
                    OPENSSL_free(sig_der);
                }
                signatures_der.clear();
                signature_lengths.clear();
                
                return false;
            }

            // Convert signature to DER format
            unsigned char* sig_der = nullptr;
            int sig_len = i2d_ECDSA_SIG(signature, &sig_der);
            if (sig_len <= 0) {
                fprintf(stderr, "Error: Failed to convert signature to DER format for commitment %zu\n", i);
                ECDSA_SIG_free(signature);
                EC_KEY_free(ecdsa_key);
                
                // Clean up any signatures we've created so far
                for (auto sig_der : signatures_der) {
                    OPENSSL_free(sig_der);
                }
                signatures_der.clear();
                signature_lengths.clear();
                
                return false;
            }

            // Store the signature
            signatures_der.push_back(sig_der);
            signature_lengths.push_back(sig_len);

            // Free the signature structure (we keep the DER format)
            ECDSA_SIG_free(signature);
        }

        // 3. Send the number of signatures
        int num_signatures = signatures_der.size();
        io->send_data(&num_signatures, sizeof(int));

        // 4. Send each signature
        for (size_t i = 0; i < signatures_der.size(); i++) {
            io->send_data(&signature_lengths[i], sizeof(int));
            io->send_data(signatures_der[i], signature_lengths[i]);
        }

        // 5. Clean up resources
        EC_KEY_free(ecdsa_key);
        
        signatures_valid = true;
        return true;
    }

    /**
     * Verifies individual signatures for each commitment using a public key from file
     * 
     * @param com Commitment points that were signed
     * @param chunk_len Length of the commitment vector
     * @param key_path Path to the PEM file containing public key
     * @return true if all signatures are valid, false otherwise
     */
    bool verify_commitment_signature(
        const ec_t* com,
        size_t chunk_len,
        const string& key_path
    ) {
        // Clean up any previous signature data
        for (auto sig_der : signatures_der) {
            OPENSSL_free(sig_der);
        }
        signatures_der.clear();
        signature_lengths.clear();
        
        if (public_key_bytes != nullptr) {
            OPENSSL_free(public_key_bytes);
            public_key_bytes = nullptr;
            public_key_len = 0;
        }
        
        signatures_valid = false;

        // 1. Load the public key from file
        EC_KEY* verify_key = nullptr;
        FILE* key_file = fopen(key_path.c_str(), "r");
        if (!key_file) {
            fprintf(stderr, "Error: Could not open ECDSA public key file at %s\n", key_path.c_str());
            return false;
        }

        verify_key = PEM_read_EC_PUBKEY(key_file, nullptr, nullptr, nullptr);
        fclose(key_file);

        if (!verify_key) {
            fprintf(stderr, "Error: Invalid ECDSA public key format\n");
            return false;
        }

        // Store the public key in the member variable for later use
        public_key_len = i2o_ECPublicKey(verify_key, &public_key_bytes);
        if (public_key_len <= 0) {
            fprintf(stderr, "Error: Failed to export public key\n");
            EC_KEY_free(verify_key);
            return false;
        }

        // 2. Receive the number of signatures
        int num_signatures;
        io->recv_data(&num_signatures, sizeof(int));
        
        if (num_signatures != (int)chunk_len) {
            fprintf(stderr, "Error: Number of signatures (%d) does not match number of commitments (%zu)\n", 
                    num_signatures, chunk_len);
            EC_KEY_free(verify_key);
            return false;
        }

        // 3. Receive and verify each signature
        for (size_t i = 0; i < chunk_len; i++) {
            // Receive signature length and data
            int sig_len;
            io->recv_data(&sig_len, sizeof(int));
            
            unsigned char* sig_der = (unsigned char*)OPENSSL_malloc(sig_len);
            if (!sig_der) {
                fprintf(stderr, "Error: Memory allocation failed for signature %zu\n", i);
                EC_KEY_free(verify_key);
                
                // Clean up any signatures we've received so far
                for (auto stored_sig : signatures_der) {
                    OPENSSL_free(stored_sig);
                }
                signatures_der.clear();
                signature_lengths.clear();
                
                return false;
            }
            
            io->recv_data(sig_der, sig_len);
            
            // Store the signature
            signatures_der.push_back(sig_der);
            signature_lengths.push_back(sig_len);
            
            // Convert the commitment to binary format
            int compressed_size = ec_size_bin(com[0], 1);
            unsigned char point_buffer[compressed_size];
            ec_write_bin(point_buffer, compressed_size, com[i], 1);
            
            // Hash the commitment
            Hash commitment_hash;
            commitment_hash.put(point_buffer, compressed_size);
            unsigned char digest[Hash::DIGEST_SIZE];
            commitment_hash.digest(digest);
            
            // Parse the signature
            ECDSA_SIG* signature = nullptr;
            const unsigned char* sig_ptr = sig_der;
            signature = d2i_ECDSA_SIG(&signature, &sig_ptr, sig_len);
            if (!signature) {
                fprintf(stderr, "Error: Failed to parse signature for commitment %zu\n", i);
                EC_KEY_free(verify_key);
                return false;
            }
            
            // Verify the signature
            int verify_result = ECDSA_do_verify(digest, Hash::DIGEST_SIZE, signature, verify_key);
            ECDSA_SIG_free(signature);
            
            if (verify_result != 1) {
                fprintf(stderr, "Error: Signature verification failed for commitment %zu\n", i);
                EC_KEY_free(verify_key);
                return false;
            }
        }

        // 4. Clean up resources
        EC_KEY_free(verify_key);
        
        signatures_valid = true;
        return true;
    }

    /**
     * Checks if valid signatures exist for all commitments
     * @return true if valid signatures exist, false otherwise
     */
    bool has_valid_signature() const {
        return signatures_valid && !signatures_der.empty();
    }
    
    /**
     * Gets signature information (for debugging or display)
     * @return string containing information about the signatures
     */
    string get_signature_info() const {
        if (!has_valid_signature()) {
            return "No valid signatures";
        }
        
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "Valid signatures: %zu signatures, total %d bytes", 
                 signatures_der.size(), 
                 std::accumulate(signature_lengths.begin(), signature_lengths.end(), 0));
        return string(buffer);
    }
};

#endif // PRIMUS_COM_COV_H
