#include "protocol/com_conv.h"
#include "backend/backend.h"
#include "backend/bn_utils.h"
#include "emp-zk/emp-zk.h"
#include "emp-ot/emp-ot.h"
#include <iostream>
#include "backend/switch.h"

#include <chrono>

extern "C" {
#include <relic/relic.h>
#include <relic/relic_core.h>
#include <relic/relic_types.h>
}

using namespace std;
using namespace emp;

template <typename IO>
void com_conv_test(
  IO* io, COT<IO>* cot, block Delta, int party, Integer& input, size_t array_len) {


    if (core_init() != RLC_OK) {
        core_clean();
    }

    // Initialize the BLS12-446 / Ed25519 curve
    if (ec_param_set_any() != RLC_OK) {
        core_clean();
    }
    
    // Define the order of the curve
    // EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    // BIGNUM* q = BN_new();
    // BN_CTX* ctx = BN_CTX_new();
    // BN_copy(q, EC_GROUP_get0_order(group));
    bn_t q;
    bn_null(q);
    bn_new(q);
    ec_curve_get_ord(q);

    // Generate random scalars
    // BIGNUM* sa = BN_new();
    // BIGNUM* sb = BN_new();
    // BIGNUM* s = BN_new();
    bn_t sa;
    bn_null(sa);
    bn_new(sa);
    bn_t sb;
    bn_null(sb);
    bn_new(sb);
    bn_t s;
    bn_null(s);
    bn_new(s);
    if (party == ALICE) {
        // BN_rand_range(sa, EC_GROUP_get0_order(group));
        bn_rand_mod(sa, q);
        send_bn(io, sa);
        recv_bn(io, sb);
    } else {
        // BN_rand_range(sb, EC_GROUP_get0_order(group));
        bn_rand_mod(sb, q);
        recv_bn(io, sa);
        send_bn(io, sb);
    }
    // BN_mod_add(s, sa, sb, EC_GROUP_get0_order(group), ctx);
    bn_add(s, sa, sb);
    bn_mod(s, s, q);
    // EC_POINT* h = EC_POINT_new(group);
    // EC_POINT_mul(group, h, s, NULL, NULL, ctx);
    ec_t h;
    ec_null(h);
    ec_new(h);
    ec_mul_gen(h, s);

    vector<block> raw(array_len);
    for (size_t i = 0; i < raw.size(); i++)
        raw[i] = input[i].bit;

    // Edwards curve does not support 255 batch size because
    // the prime size is <255 bits. We are making it 252 instead 
    // as it is the biggest batch size bs such that 2^bs < q (the size of the curve).
    size_t batch_size = 252;
    size_t chunk_len = (array_len + batch_size - 1) / batch_size;
    // vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;
    // vector<ec_t> coms; // = new ec_t[chunk_len];
    ec_t coms[chunk_len];
    // bn_st** rnds = new bn_st*[chunk_len];

    rnds.resize(chunk_len);
    // coms.resize(chunk_len);

    // Initialize
    for (size_t i = 0; i < chunk_len; i++) {
        ec_null(coms[i]);
        ec_new(coms[i]);
        // bn_null(rnds[i]);
        // bn_new(rnds[i]);
        rnds[i] = BN_new();
    }

    // for (size_t i = 0; i < chunk_len; i++) {
    //     coms[i] = EC_POINT_new(group);
    //     rnds[i] = BN_new();
    // }

    size_t comm = io->counter;
    BIGNUM* openssl_q = relic_bn_to_openssl_bignum(q);
    if (openssl_q == NULL) {
        std::cerr << "Error: Failed to convert RELIC bn_t to OpenSSL BIGNUM." << std::endl;
        std::exit(EXIT_FAILURE); // or return a non-zero code if in main()
    }
    ComConv<IO> conv(io, cot, openssl_q, Delta);
    RelicPedersenComm pc(h);

    if (party == BOB) {
        auto start = emp::clock_start();
        bool res = conv.compute_com_send(coms, raw, pc, batch_size);
        if (res) {
            cout << "BOB check passed" << endl;
        } else {
            cout << "BOB check failed" << endl;
        }
        cout << "BOB time: " << emp::time_from(start) << " us" << endl;
        cout << "BOB comm: " << io->counter - comm << " bytes" << endl;
    } else {
        auto start = emp::clock_start();
        bool res = conv.compute_com_recv(coms, rnds, raw, pc, batch_size);
        if (res) {
            cout << "ALICE check passed" << endl;
        } else {
            cout << "ALICE check failed" << endl;
        }
        cout << "ALICE time: " << emp::time_from(start) << " us" << endl;
        cout << "ALICE comms: " << io->counter - comm << " bytes" << endl;
    }

    // // for (size_t i = 0; i < chunk_len; i++) {
    // //     EC_POINT_free(coms[i]);
    // //     BN_free(rnds[i]);
    // // }

    // // // Cleanup
    // // for (size_t i = 0; i < chunk_len; ++i) {
    // //     ep_free(coms[i]);
    // //     bn_free(rnds[i]);
    // // }
    // // delete[] coms;
    // // delete[] rnds;
}

const int threads = 4;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        // io[i] = new NetIO(party == ALICE ? nullptr : "104.198.159.189", port + i);
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);
    }

    setup_protocol<NetIO>(io[0], ios, threads, party);

    switch_to_zk();

    IKNP<NetIO>* cot = ((PrimusParty<NetIO>*)(gc_prot_buf))->ot;
    FerretCOT<NetIO>* fcot;
    if (party == ALICE) {
        fcot = ((ZKProver<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    } else {
        fcot = ((ZKVerifier<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    }

    size_t array_len = 4 * 1024 * 8;
    PRG prg;
    unsigned char* val = new unsigned char[array_len / 8];
    prg.random_data(val, array_len / 8);
    Integer input(array_len, val, ALICE);
    ios[0]->flush();

    com_conv_test<NetIO>(io[0], cot, fcot->Delta, party, input, array_len);
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
