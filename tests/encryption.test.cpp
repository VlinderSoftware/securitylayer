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
#include "../details/aes256cbcencryption.hpp"
#include "deterministicrandomnumbergenerator.hpp"

using namespace DNP3SAv6;
using namespace boost::asio;

TEST_CASE( "Test vectors for AES CBC encryption (1)", "[aes256cbc]" ) {
	unsigned char const key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	unsigned char const initialization_vector[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	unsigned char const plaintext[] = { 'S', 'i', 'n', 'g', 'l', 'e', ' ', 'b', 'l', 'o', 'c', 'k', ' ', 'm', 's', 'g' };
    unsigned char const expected_ciphertext[] = {
          0x8d, 0xbf, 0x0e, 0x59, 0xa3, 0xe4, 0xe9, 0x03, 0x4f, 0xc5, 0x20, 0x88, 0x7e, 0x7f, 0x98, 0x19
        , 0x48, 0x42, 0x71, 0x77, 0xc4, 0x06, 0xbe, 0x35, 0xf1, 0x3f, 0xbc, 0xaa, 0xdb, 0xda, 0xde, 0x07
        };

	unsigned char ciphertext[sizeof(expected_ciphertext)];
	mutable_buffer ciphertext_buffer(ciphertext, sizeof(ciphertext));

    {
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
        { // implementation sanity check
            auto returned_iv(encryption.getIV());
            REQUIRE( returned_iv.data() != &initialization_vector );
            REQUIRE( returned_iv.size() == sizeof(initialization_vector) );
            REQUIRE( memcmp(returned_iv.data(), initialization_vector, sizeof(initialization_vector)) == 0 );
        }
        { // encrypt and verify ciphertext 
            auto ciphertext_output(encryption.encrypt(ciphertext_buffer, const_buffer(key, sizeof(key)), const_buffer(plaintext, sizeof(plaintext))));
            REQUIRE( ciphertext_output.data() == ciphertext_buffer.data() );
            REQUIRE( ciphertext_output.size() == ciphertext_buffer.size() );
            REQUIRE( memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) == 0) ;
        }
    }
    { // decrypt and verify cleartext
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
	    unsigned char decrypted[sizeof(ciphertext)];
	    mutable_buffer decrypted_buffer(decrypted, sizeof(decrypted));
        auto decrypt_output(encryption.decrypt(decrypted_buffer, const_buffer(key, sizeof(key)), ciphertext_buffer));
        REQUIRE( decrypt_output.data() == decrypted_buffer.data() );
        REQUIRE( decrypt_output.size() == sizeof(plaintext) );
        REQUIRE( memcmp(decrypted, plaintext, sizeof(plaintext)) == 0) ;
    }
}

TEST_CASE( "Test vectors for AES CBC encryption (2)", "[aes256cbc]" ) {
	unsigned char const key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	unsigned char const initialization_vector[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	unsigned char const plaintext[1] = { 0x00 };
    unsigned char const expected_ciphertext[] = {
          0x9e, 0x5e, 0x32, 0xbb, 0x33, 0xe1, 0x7f, 0x81, 0x22, 0x72, 0x7f, 0x89, 0x92, 0x18, 0x30, 0x93
        };

	unsigned char ciphertext[64];
	mutable_buffer ciphertext_buffer(ciphertext, sizeof(ciphertext));

    {
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
        { // encrypt and verify ciphertext 
            auto ciphertext_output(encryption.encrypt(ciphertext_buffer, const_buffer(key, sizeof(key)), const_buffer(plaintext, sizeof(plaintext))));
            REQUIRE( ciphertext_output.data() == ciphertext_buffer.data() );
            REQUIRE( ciphertext_output.size() == sizeof(expected_ciphertext) );
            REQUIRE( memcmp(ciphertext, expected_ciphertext, sizeof(expected_ciphertext)) == 0) ;
        }
    }
    { // decrypt and verify cleartext
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
	    unsigned char decrypted[sizeof(ciphertext)];
	    mutable_buffer decrypted_buffer(decrypted, sizeof(decrypted));
        ciphertext_buffer = mutable_buffer(ciphertext, 16);
        auto decrypt_output(encryption.decrypt(decrypted_buffer, const_buffer(key, sizeof(key)), ciphertext_buffer));
        REQUIRE( decrypt_output.data() == decrypted_buffer.data() );
        REQUIRE( decrypt_output.size() == sizeof(plaintext) );
        REQUIRE( memcmp(decrypted, plaintext, sizeof(plaintext)) == 0) ;
    }
}

TEST_CASE( "Test vectors for AES CBC encryption (3): trailing junk", "[aes256cbc]" ) {
	unsigned char const key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	unsigned char const initialization_vector[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	unsigned char const plaintext[1] = { 0x00 };
    unsigned char const expected_ciphertext[] = {
          0x9e, 0x5e, 0x32, 0xbb, 0x33, 0xe1, 0x7f, 0x81, 0x22, 0x72, 0x7f, 0x89, 0x92, 0x18, 0x30, 0x93
        };

	unsigned char ciphertext[64];
	mutable_buffer ciphertext_buffer(ciphertext, sizeof(ciphertext));
	Tests::DeterministicRandomNumberGenerator rng;
    rng.generate(ciphertext_buffer);
    {
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
        { // encrypt and verify ciphertext 
            auto ciphertext_output(encryption.encrypt(ciphertext_buffer, const_buffer(key, sizeof(key)), const_buffer(plaintext, sizeof(plaintext))));
            REQUIRE( ciphertext_output.data() == ciphertext_buffer.data() );
            REQUIRE( ciphertext_output.size() == sizeof(expected_ciphertext) );
            REQUIRE( memcmp(ciphertext, expected_ciphertext, sizeof(expected_ciphertext)) == 0) ;
        }
    }
    { // decrypt and verify there is no cleartext
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
	    unsigned char decrypted[sizeof(ciphertext)];
	    mutable_buffer decrypted_buffer(decrypted, sizeof(decrypted));
        auto decrypt_output(encryption.decrypt(decrypted_buffer, const_buffer(key, sizeof(key)), ciphertext_buffer));
        REQUIRE( decrypt_output.size() == 0 );
    }
}

TEST_CASE( "Test vectors for AES CBC encryption (4): non-modulo-sixteen input length", "[aes256cbc]" ) {
	unsigned char const key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	unsigned char const initialization_vector[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	unsigned char ciphertext[63];
	mutable_buffer ciphertext_buffer(ciphertext, sizeof(ciphertext));
	Tests::DeterministicRandomNumberGenerator rng;
    rng.generate(ciphertext_buffer);
    { // decrypt and verify there is no cleartext
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
	    unsigned char decrypted[sizeof(ciphertext) + (16 - (sizeof(ciphertext) % 16))];
	    mutable_buffer decrypted_buffer(decrypted, sizeof(decrypted));
        auto decrypt_output(encryption.decrypt(decrypted_buffer, const_buffer(key, sizeof(key)), ciphertext_buffer));
        REQUIRE( decrypt_output.size() == 0 );
    }
}

TEST_CASE( "Test vectors for AES CBC encryption (4): pure junk", "[aes256cbc]" ) {
	unsigned char const key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	unsigned char const initialization_vector[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	unsigned char ciphertext[64];
	mutable_buffer ciphertext_buffer(ciphertext, sizeof(ciphertext));
	Tests::DeterministicRandomNumberGenerator rng;
    rng.generate(ciphertext_buffer);
    { // decrypt and verify there is no cleartext
	    Details::AES256CBCEncryption encryption;
        encryption.setIV(const_buffer(initialization_vector, sizeof(initialization_vector)));
	    unsigned char decrypted[sizeof(ciphertext) + (16 - (sizeof(ciphertext) % 16))];
	    mutable_buffer decrypted_buffer(decrypted, sizeof(decrypted));
        auto decrypt_output(encryption.decrypt(decrypted_buffer, const_buffer(key, sizeof(key)), ciphertext_buffer));
        REQUIRE( decrypt_output.size() == 0 );
    }
}

