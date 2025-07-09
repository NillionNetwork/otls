#include "protocol/com_conv_g2.h"
#include "backend/backend.h"
#include "backend/bn_utils.h"
#include "emp-zk/emp-zk.h"
#include "emp-ot/emp-ot.h"
#include <iostream>
#include <fstream>
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

    // Initialize the BLS12-446 G2 groups
    if (pc_param_set_any() != RLC_OK) {
        core_clean();
    }
    
    // Define the order of the curve
    // EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v0);
    // BIGNUM* q = BN_new();
    // BN_CTX* ctx = BN_CTX_new();
    // BN_copy(q, EC_GROUP_get0_order(group));
    bn_t q;
    bn_null(q);
    bn_new(q);
    g2_get_ord(q);

    // Generate random scalars
    // BIGNUM* sa = BN_new();
    // BIGNUM* sb = BN_new();
    // BIGNUM* s = BN_new();
    bn_t sa; bn_null(sa); bn_new(sa);
    bn_t sb; bn_null(sb); bn_new(sb);
    g2_t ha; g2_null(ha); g2_new(ha);
    g2_t hb; g2_null(hb); g2_new(hb);
    if (party == ALICE) {
        // BN_rand_range(sa, EC_GROUP_get0_order(group));
        bn_rand_mod(sa, q);
        g2_mul_gen(ha, sa);
        int compressed_size = g2_size_bin(ha, 1);  // 1 for compressed format
        unsigned char* buf = (unsigned char*)malloc(compressed_size);  // RELIC points are 65 bytes uncompressed
        
        // Sending ha
        g2_write_bin(buf, compressed_size, ha, 1);
        io->send_data(buf, compressed_size);
        
        // Receiving hb
        io->recv_data(buf, compressed_size);
        g2_read_bin(hb, buf, compressed_size);
        // send_bn(io, sa);
        // recv_bn(io, sb);
    } else {
        // BN_rand_range(sb, EC_GROUP_get0_order(group));
        bn_rand_mod(sb, q);
        g2_mul_gen(hb, sb);
        int compressed_size = g2_size_bin(hb, 1);  // 1 for compressed format
        unsigned char* buf = (unsigned char*)malloc(compressed_size);  // RELIC points are 65 bytes uncompressed

        // Receiving ha
        io->recv_data(buf, compressed_size);
        g2_read_bin(ha, buf, compressed_size);
        
        // Sending hb
        g2_write_bin(buf, compressed_size, hb, 1);
        io->send_data(buf, compressed_size);


        // recv_bn(io, sa);
        // send_bn(io, sb);
    }
    // // BN_mod_add(s, sa, sb, EC_GROUP_get0_order(group), ctx);
    // bn_add(s, sa, sb);
    // bn_mod(s, s, q);
    // // EC_POINT* h = EC_POINT_new(group);
    // // EC_POINT_mul(group, h, s, NULL, NULL, ctx);
    g2_t h; g2_null(h); g2_new(h);
    g2_add(h, ha, hb);

    vector<block> raw(array_len);
    for (size_t i = 0; i < raw.size(); i++)
        raw[i] = input[i].bit;

    // In the fhe mode, we are only picking 4 bits because we will batch them together in just
    // one block. This simulates the case where we pick one block of bits to be fhe encrypted 
    // while redacting the rest. Thus, we define the batch size to be 4 and total array length
    // to be 4 as well.
    size_t batch_size = 4;
    size_t chunk_len = (array_len + batch_size - 1) / batch_size;
    // vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;
    // vector<ec_t> coms; // = new ec_t[chunk_len];
    g2_t coms[chunk_len];
    // bn_st** rnds = new bn_st*[chunk_len];

    rnds.resize(chunk_len);
    // coms.resize(chunk_len);

    // Initialize
    for (size_t i = 0; i < chunk_len; i++) {
        g2_null(coms[i]);
        g2_new(coms[i]);
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

    // // Initialize
    // ec_t relic_comms[chunk_len];
    // for (size_t i = 0; i < chunk_len; i++) {
    //     ec_null(relic_comms[i]);
    //     ec_new(relic_comms[i]);
    // }

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
        auto [res, msg, signatures_der, signature_lengths] = conv.compute_com_recv(coms, rnds, raw, pc, batch_size);
        
        if (res) {
            cout << "ALICE check passed" << endl;
        } else {
            cout << "ALICE check failed" << endl;
        }
        cout << "ALICE time: " << emp::time_from(start) << " us" << endl;
        cout << "ALICE comms: " << io->counter - comm << " bytes" << endl;
    

        // Write all signatures to file (overwrite mode to match commitments.bin behavior)
        std::ofstream sig_file("shared_bin/signatures.bin", std::ios::binary);
        for (size_t i = 0; i < signatures_der.size(); i++) {
            sig_file.write(reinterpret_cast<const char*>(&signature_lengths[i]), sizeof(int));
            sig_file.write(reinterpret_cast<const char*>(signatures_der[i]), signature_lengths[i]);
        }
        sig_file.close();
        cout << "ALICE: Written " << signatures_der.size() << " signatures to signatures.bin" << endl;

        // Write the commitments to file
        std::ofstream binary_file("shared_bin/commitments.bin", std::ios::binary);
        int compressed_size = g2_size_bin(coms[0], 1);
        unsigned char* buf = new unsigned char[compressed_size];  
        for (size_t i = 0; i < chunk_len; i++) {
            g2_write_bin(buf, compressed_size, coms[i], 1);
            binary_file.write(reinterpret_cast<const char*>(buf), compressed_size);
        }
        delete(buf);
        binary_file.close();
        cout << "ALICE: Written " << chunk_len << " commitments to commitments.bin" << endl;

        // Write messages to file
        std::ofstream msg_file("shared_bin/messages.bin", std::ios::binary);
        for (size_t i = 0; i < chunk_len; i++) {
            // Convert BIGNUM to binary
            int msg_size = BN_num_bytes(msg[i]);
            unsigned char* msg_buf = new unsigned char[msg_size];
            BN_bn2bin(msg[i], msg_buf);
            
            // Write size first, then the message data
            msg_file.write(reinterpret_cast<const char*>(&msg_size), sizeof(int));
            msg_file.write(reinterpret_cast<const char*>(msg_buf), msg_size);
            
            delete[] msg_buf;
        }
        msg_file.close();
        cout << "ALICE: Written " << chunk_len << " message values to messages.bin" << endl;

        // // Create and save BN number 7
        // BIGNUM* test_bn = BN_new();
        // BN_set_word(test_bn, 7);
        
        // std::ofstream bn_file("shared_bin/test_bn.bin", std::ios::binary);
        // int bn_size = BN_num_bytes(test_bn);
        // unsigned char* bn_buf = new unsigned char[bn_size];
        // BN_bn2bin(test_bn, bn_buf);
        
        // // Write size first, then the BN data
        // bn_file.write(reinterpret_cast<const char*>(&bn_size), sizeof(int));
        // bn_file.write(reinterpret_cast<const char*>(bn_buf), bn_size);
        
        // delete[] bn_buf;
        // BN_free(test_bn);
        // bn_file.close();
        // cout << "ALICE: Written test BN value 7 to test_bn.bin" << endl;


        // Write randomness rnds to file
        std::ofstream rnd_file("shared_bin/randomness.bin", std::ios::binary);
        for (size_t i = 0; i < chunk_len; i++) {
            // Convert BIGNUM to binary
            int rnd_size = BN_num_bytes(rnds[i]);
            unsigned char* rnd_buf = new unsigned char[rnd_size];
            BN_bn2bin(rnds[i], rnd_buf);
            
            // Write size first, then the randomness data
            rnd_file.write(reinterpret_cast<const char*>(&rnd_size), sizeof(int));
            rnd_file.write(reinterpret_cast<const char*>(rnd_buf), rnd_size);
            
            delete[] rnd_buf;
        }
        rnd_file.close();
        cout << "ALICE: Written " << chunk_len << " randomness values to randomness.bin" << endl;

        // Write h to file
        // std::ofstream h_file("../pvss/src/aux_data/h_value.bin", std::ios::binary);
        std::ofstream h_file("shared_bin/h_value.bin", std::ios::binary);
        int h_compressed_size = g2_size_bin(h, 1);
        unsigned char* h_buf = new unsigned char[h_compressed_size];
        g2_write_bin(h_buf, h_compressed_size, h, 1);
        h_file.write(reinterpret_cast<const char*>(h_buf), h_compressed_size);
        delete(h_buf);
        h_file.close();
        cout << "ALICE: Written h value to h_value.bin (" << h_compressed_size << " bytes)" << endl;
        
        // Clean up the msg vector
        for (size_t i = 0; i < chunk_len; i++) {
            BN_free(msg[i]);
        }
    }

    // for (size_t i = 0; i < chunk_len; i++) {
    //     EC_POINT_free(coms[i]);
    //     BN_free(rnds[i]);
    // }

    // Cleanup
    for (size_t i = 0; i < chunk_len; ++i) {
        ep_free(coms[i]);
        bn_free(rnds[i]);
    }
    // delete[] coms;
    // delete[] rnds;
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

    // size_t array_len = 2 * 1024 * 8;
    // In the fhe mode, we are only picking 4 bits because we will batch them together in just
    // one block. This simulates the case where we pick one block of bits to be fhe encrypted 
    // while redacting the rest. Thus, we define the batch size to be 4 and total array length
    // to be 4 as well.
    size_t array_len = 4;
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
