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
#include "../details/hmacsha256.hpp"
#include "../details/aeadhmacadapter.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../aead.hpp"
#include "../hmac.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace boost::asio;
using namespace DNP3SAv6;
using namespace DNP3SAv6::Details;

TEST_CASE( "HMAC SHA-2 256 create instance", "[aead-hmac-sha2-256]" ) {
    REQUIRE( getKeySize< AEADHMACAdapter< HMACSHA256, AEADAlgorithm::hmac_sha_256_truncated_8__ > >() == 32 );
    mutable_buffer out;
    const_buffer key;
    const_buffer nonce;
    const_buffer associated_data;
    IAEAD const &aead(makeAEAD< AEADHMACAdapter< HMACSHA256, AEADAlgorithm::hmac_sha_256_truncated_8__ > >(out, key, nonce, associated_data));
}

TEST_CASE( "HMAC SHA-2 256 'encrypt' data", "[aead-hmac-sha2-256]" ) {
    unsigned char const spdu_header[] = { 0xC0, 0x80, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00 };
    unsigned char key[getKeySize< AEADHMACAdapter< HMACSHA256, AEADAlgorithm::hmac_sha_256_truncated_8__ > >()];
	Tests::DeterministicRandomNumberGenerator rng;
    rng.generate(mutable_buffer(key, sizeof(key)));
    unsigned char const payload[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        , 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
    unsigned char aead_out[sizeof(payload) + 8] = { 0 };
    unsigned char digest_out[8] = { 0 };
    unsigned char const expected_aead_result[] = { 
        // HMAC AEAD copies the data, but not associated data or the nonce
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        , 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        , 0x38, 0xac, 0x5f, 0x12, 0x68, 0x1b, 0x20, 0x2b 
        };
    unsigned char const expected_digest[] = { 
          0x38, 0xac, 0x5f, 0x12, 0x68, 0x1b, 0x20, 0x2b 
        };
    unsigned char decrypted_payload[2 * sizeof(payload)] = { 0 };

    {   // run as AEAD
        const_buffer nonce(spdu_header + 4, 4);
        const_buffer associated_data(spdu_header, 4);
        const_buffer key_buffer(key, sizeof(key));
        const_buffer payload_buffer(payload, sizeof(payload));
        mutable_buffer out_buffer(aead_out, sizeof(aead_out));
        auto encrypt_result(encrypt(out_buffer, AEADAlgorithm::hmac_sha_256_truncated_8__, key_buffer, nonce, associated_data, payload_buffer));
        REQUIRE( encrypt_result.data() == &aead_out );
        REQUIRE( encrypt_result.size() == sizeof(aead_out) );
        static_assert(sizeof(aead_out) == sizeof(expected_aead_result), "logic error in the test case");
        REQUIRE( memcmp(aead_out, expected_aead_result, sizeof(expected_aead_result)) == 0 );
    }
    
    { // run as digest
        mutable_buffer out_buffer(digest_out, sizeof(digest_out));
        const_buffer key_buffer(key, sizeof(key));
        const_buffer header_buffer(spdu_header, sizeof(spdu_header));
        const_buffer payload_buffer(payload, sizeof(payload));
        digest(out_buffer, AEADAlgorithm::hmac_sha_256_truncated_8__, key_buffer, header_buffer, payload_buffer);
        static_assert(sizeof(digest_out) == sizeof(expected_digest), "logic error in the test case");
        REQUIRE( memcmp(digest_out, expected_digest, sizeof(expected_digest)) == 0 );
    }

    { // verify 
        const_buffer incoming_digest(digest_out, sizeof(digest_out));
        const_buffer key_buffer(key, sizeof(key));
        const_buffer header_buffer(spdu_header, sizeof(spdu_header));
        const_buffer payload_buffer(payload, sizeof(payload));
        REQUIRE( verify(incoming_digest, AEADAlgorithm::hmac_sha_256_truncated_8__, key_buffer, header_buffer, payload_buffer) );
    }

    { // decrypt
        const_buffer key_buffer(key, sizeof(key));
        const_buffer nonce(spdu_header + 4, 4);
        const_buffer associated_data(spdu_header, 4);
        mutable_buffer out_buffer(aead_out, sizeof(aead_out));
        auto decrypt_result(decrypt(mutable_buffer(decrypted_payload, sizeof(decrypted_payload)), AEADAlgorithm::hmac_sha_256_truncated_8__, key_buffer, nonce, associated_data, out_buffer));
        REQUIRE( decrypt_result.data() == &decrypted_payload );
        REQUIRE( decrypt_result.size() == sizeof(payload) );
        REQUIRE( memcmp(decrypt_result.data(), payload, decrypt_result.size()) == 0 );
    }
}
