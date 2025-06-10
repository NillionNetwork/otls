#include <openssl/bn.h>
#include <iostream>
#include <cassert>

#include "backend/bn_utils.h"

extern "C" {
#include <relic/relic.h>
#include <relic/relic_core.h>
#include <relic/relic_types.h>
}

void print_bn(const BIGNUM* bn, const char* label) {
    char* str = BN_bn2hex(bn);
    std::cout << label << ": " << str << std::endl;
    OPENSSL_free(str);
}

void print_relic_bn(const bn_t bn, const char* label) {
    char str[1024];
    bn_write_str(str, sizeof(str), bn, 16);
    std::cout << label << ": " << str << std::endl;
}

// Debug function to print binary data
void print_binary(const unsigned char* data, int len, const char* label) {
    std::cout << label << " (hex): ";
    for(int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    std::cout << std::endl;
}

int main() {
    // Initialize RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    // Test 1: Small positive number (42)
    std::cout << "\nTest 1: Small positive number (42)" << std::endl;
    {
        // Create RELIC number
        bn_t relic_num;
        bn_null(relic_num);
        bn_new(relic_num);
        bn_set_dig(relic_num, 42);

        // Print original RELIC number
        print_relic_bn(relic_num, "Original RELIC number");

        // Get binary size and data
        int size = bn_size_bin(relic_num);
        unsigned char* buffer = new unsigned char[size];
        bn_write_bin(buffer, size, relic_num);
        
        // Print binary data
        print_binary(buffer, size, "RELIC binary data");

        // Create OpenSSL BIGNUM from binary data
        BIGNUM* openssl_num = BN_bin2bn(buffer, size, NULL);
        assert(openssl_num != nullptr);

        // Print OpenSSL number
        print_bn(openssl_num, "OpenSSL number");

        // Get binary data from OpenSSL
        int openssl_size = BN_num_bytes(openssl_num);
        unsigned char* openssl_buffer = new unsigned char[openssl_size];
        BN_bn2bin(openssl_num, openssl_buffer);
        
        // Print OpenSSL binary data
        print_binary(openssl_buffer, openssl_size, "OpenSSL binary data");

        // Convert back to RELIC
        bn_t relic_num2;
        bn_null(relic_num2);
        bn_new(relic_num2);
        bn_read_bin(relic_num2, openssl_buffer, openssl_size);

        // Print the converted back number
        print_relic_bn(relic_num2, "RELIC number (converted back)");

        // Verify the numbers match
        if (bn_cmp(relic_num, relic_num2) == RLC_EQ) {
            std::cout << "Numbers match!" << std::endl;
        } else {
            std::cout << "Numbers don't match!" << std::endl;
        }

        // Cleanup
        delete[] buffer;
        delete[] openssl_buffer;
        BN_free(openssl_num);
        bn_free(relic_num);
        bn_free(relic_num2);
    }

    // Test 2: Large number (2^64 - 1)
    std::cout << "\nTest 2: Large number (2^64 - 1)" << std::endl;
    {
        // Create RELIC number
        bn_t relic_num;
        bn_null(relic_num);
        bn_new(relic_num);
        bn_set_2b(relic_num, 64);
        bn_sub_dig(relic_num, relic_num, 1);

        // Print original RELIC number
        print_relic_bn(relic_num, "Original RELIC number");

        // Get binary size and data
        int size = bn_size_bin(relic_num);
        unsigned char* buffer = new unsigned char[size];
        bn_write_bin(buffer, size, relic_num);
        
        // Print binary data
        print_binary(buffer, size, "RELIC binary data");

        // Create OpenSSL BIGNUM from binary data
        BIGNUM* openssl_num = BN_bin2bn(buffer, size, NULL);
        assert(openssl_num != nullptr);

        // Print OpenSSL number
        print_bn(openssl_num, "OpenSSL number");

        // Get binary data from OpenSSL
        int openssl_size = BN_num_bytes(openssl_num);
        unsigned char* openssl_buffer = new unsigned char[openssl_size];
        BN_bn2bin(openssl_num, openssl_buffer);
        
        // Print OpenSSL binary data
        print_binary(openssl_buffer, openssl_size, "OpenSSL binary data");

        // Convert back to RELIC
        bn_t relic_num2;
        bn_null(relic_num2);
        bn_new(relic_num2);
        bn_read_bin(relic_num2, openssl_buffer, openssl_size);

        // Print the converted back number
        print_relic_bn(relic_num2, "RELIC number (converted back)");

        // Verify the numbers match
        if (bn_cmp(relic_num, relic_num2) == RLC_EQ) {
            std::cout << "Numbers match!" << std::endl;
        } else {
            std::cout << "Numbers don't match!" << std::endl;
        }

        // Cleanup
        delete[] buffer;
        delete[] openssl_buffer;
        BN_free(openssl_num);
        bn_free(relic_num);
        bn_free(relic_num2);
    }

    // Test 3: Vector conversions
    std::cout << "\nTest 3: Vector conversions" << std::endl;
    {
        // Create arrays of RELIC numbers
        bn_t relic_nums[3];
        bn_t relic_nums2[3];

        // Initialize all numbers
        for (int i = 0; i < 3; i++) {
            bn_null(relic_nums[i]);
            bn_null(relic_nums2[i]);
            bn_new(relic_nums[i]);
            bn_new(relic_nums2[i]);
            bn_set_dig(relic_nums[i], 42 + i);  // 42, 43, 44
        }

        // Print original RELIC numbers
        std::cout << "Original RELIC numbers:" << std::endl;
        for (size_t i = 0; i < 3; i++) {
            print_relic_bn(relic_nums[i], ("RELIC number " + std::to_string(i)).c_str());
        }

        // Convert to OpenSSL BIGNUMs
        std::vector<BIGNUM*> openssl_nums = relic_bn_vec_to_openssl_bignum_vec(relic_nums, 3);

        // Print OpenSSL numbers
        std::cout << "\nConverted OpenSSL numbers:" << std::endl;
        for (size_t i = 0; i < openssl_nums.size(); i++) {
            print_bn(openssl_nums[i], ("OpenSSL number " + std::to_string(i)).c_str());
        }

        // Convert back to RELIC
        openssl_bignum_vec_to_relic_bn_vec(relic_nums2, openssl_nums);

        // Print converted back RELIC numbers
        std::cout << "\nRELIC numbers (converted back):" << std::endl;
        for (size_t i = 0; i < 3; i++) {
            print_relic_bn(relic_nums2[i], ("RELIC number " + std::to_string(i)).c_str());
        }

        // Verify all numbers match
        bool all_match = true;
        for (size_t i = 0; i < 3; i++) {
            if (bn_cmp(relic_nums[i], relic_nums2[i]) != RLC_EQ) {
                all_match = false;
                break;
            }
        }
        std::cout << "\nAll numbers " << (all_match ? "match!" : "don't match!") << std::endl;

        // Cleanup
        for (auto& num : openssl_nums) {
            BN_free(num);
        }
        for (int i = 0; i < 3; i++) {
            bn_free(relic_nums[i]);
            bn_free(relic_nums2[i]);
        }
    }

    // Cleanup RELIC
    core_clean();
    return 0;
} 