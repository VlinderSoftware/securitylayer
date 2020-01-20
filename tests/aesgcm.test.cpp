/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "catch.hpp"
#include "../details/aesgcm.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../aead.hpp"
#include "../hmac.hpp"
#include "../exceptions/contract.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace boost::asio;
using namespace DNP3SAv6;
using namespace DNP3SAv6::Details;

TEST_CASE( "AESGCM create instance", "[aesgcm]" ) {
    REQUIRE( getKeySize< AESGCM >() == 32 );
    mutable_buffer out;
    unsigned char key_data[getKeySize< AESGCM >()] = { 0 };
    const_buffer key(key_data, sizeof(key_data));
    const_buffer nonce;
    const_buffer associated_data;
    IAEAD const &aead(makeAEAD< AESGCM >(out, key, nonce, associated_data));
}

TEST_CASE( "AESGCM encrypt data", "[aesgcm]" ) {
    unsigned char const spdu_header[] = { 0xC0, 0x80, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00 };
    unsigned char key[getKeySize< AESGCM >()];
	Tests::DeterministicRandomNumberGenerator rng;
    mutable_buffer key_buffer(key, sizeof(key));
    rng.generate(key_buffer);
    unsigned char const payload[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        , 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
    unsigned char aead_out[sizeof(payload) + 16] = { 0 };
    unsigned char const expected_aead_result[] = { 
        // HMAC AEAD copies the data, but not associated data or the nonce
          0x0c, 0xed, 0xe2, 0x1a, 0xcf, 0xc1, 0x81, 0x68, 0xdb, 0x72, 0x19, 0xaa, 0x55, 0xd9, 0x0e, 0x62
        , 0xe0, 0x31, 0x08, 0x60, 0xd2, 0x2f, 0x27, 0x82, 0x44, 0x5c, 0xe8, 0x70, 0xb0, 0x6c, 0xce, 0x09
        , 0xbb, 0x44, 0x11, 0xde, 0x80, 0x2c, 0xa9, 0x24, 0xf4, 0x4f, 0x2e, 0x3b, 0x7e, 0x58, 0x5a, 0x81
        };
    unsigned char decrypted_payload[2 * sizeof(payload)] = { 0 };

    { // encrypt
        const_buffer nonce(spdu_header + 4, 4);
        const_buffer associated_data(spdu_header, 4);
        const_buffer key_buffer(key, sizeof(key));
        const_buffer payload_buffer(payload, sizeof(payload));
        mutable_buffer out_buffer(aead_out, sizeof(aead_out));
        auto encrypt_result(encrypt(out_buffer, AEADAlgorithm::aes256_gcm__, key_buffer, nonce, associated_data, payload_buffer));
        REQUIRE( encrypt_result.data() == &aead_out );
        REQUIRE( encrypt_result.size() == sizeof(aead_out) );
        static_assert(sizeof(aead_out) == sizeof(expected_aead_result), "logic error in the test case");
        REQUIRE( memcmp(aead_out, expected_aead_result, sizeof(expected_aead_result)) == 0 );
    }

    { // decrypt
        const_buffer key_buffer(key, sizeof(key));
        const_buffer nonce(spdu_header + 4, 4);
        const_buffer associated_data(spdu_header, 4);
        mutable_buffer out_buffer(aead_out, sizeof(aead_out));
        auto decrypt_result(decrypt(mutable_buffer(decrypted_payload, sizeof(decrypted_payload)), AEADAlgorithm::aes256_gcm__, key_buffer, nonce, associated_data, out_buffer));
        REQUIRE( decrypt_result.data() == &decrypted_payload );
        REQUIRE( decrypt_result.size() == sizeof(payload) );
        REQUIRE( memcmp(decrypt_result.data(), payload, decrypt_result.size()) == 0 );
    }
}

TEST_CASE( "AESGCM used as a MAC", "[aesgcm]" ) {
    unsigned char key[getKeySize< AESGCM >()];
	Tests::DeterministicRandomNumberGenerator rng;
    mutable_buffer key_buffer(key, sizeof(key));
    rng.generate(key_buffer);
    unsigned char const payload[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        , 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
    assert(16 == getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__));
    unsigned char mac_out[16];
    unsigned char const expected_mac[16] = {
          0x1f, 0xf1, 0xf9, 0x4e, 0x92, 0x88, 0x50, 0xa7, 0xa2, 0x44, 0x6d, 0xcd, 0x5e, 0x62, 0x0c, 0xc2
        };
    digest(mutable_buffer(mac_out, sizeof(mac_out)), AEADAlgorithm::aes256_gcm__, const_buffer(key, sizeof(key)), const_buffer(payload, sizeof(payload)));
    REQUIRE( memcmp(mac_out, expected_mac, 16) == 0 );
    REQUIRE( verify(const_buffer(mac_out, sizeof(mac_out)), AEADAlgorithm::aes256_gcm__, const_buffer(key, sizeof(key)), const_buffer(payload, sizeof(payload))) );
}
