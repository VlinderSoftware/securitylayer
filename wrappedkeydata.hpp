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
#ifndef dnp3sav6_wrappedkeydata_hpp
#define dnp3sav6_wrappedkeydata_hpp

#include <cstdint>
#include <boost/asio.hpp>
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"
#include "encryptionalgorithm.hpp"

namespace DNP3SAv6 {
	/* There are a few variable-length fields in this struct as defined by the WG15 working document. IEEE 1815-2012 
	 * defines it with similar variable-length fields for SAv5. I am not a fan of variable-length fields: it makes 
	 * specs ambiguous and makes implementations harder to verify. Hence, the present proposal removes a number of 
	 * options, as well as all public data, and leaves only the keys and the MAC. This leaves four variants of the 
	 * structure to be defined - one per combination of encryption algorithm and MAC size. 
	 * The following table summarizes our options:
	 * +-----+-----+-----+--------------------------+-----------------------------+------------------+
	 * | KWA | MAL | EAL | Session key size (bytes) | Encryption key size (bytes) | MAC size (bytes) |
	 * +-----+-----+-----+--------------------------+-----------------------------+------------------+
	 * |  2  |  3  |  0  |                       32 |                           0 |                8 |
	 * |  2  |  4  |  0  |                       32 |                           0 |               16 |
	 * |  2  |  7  |  0  |                       32 |                           0 |                8 |
	 * |  2  |  8  |  0  |                       32 |                           0 |               16 |
	 * |  2  |  9  |  0  |                       32 |                           0 |                8 |
	 * |  2  | 10  |  0  |                       32 |                           0 |               16 |
	 * |  2  |  3  |  1  |                       32 |                          32 |                8 |
	 * |  2  |  4  |  1  |                       32 |                          32 |               16 |
	 * |  2  |  7  |  1  |                       32 |                          32 |                8 |
	 * |  2  |  8  |  1  |                       32 |                          32 |               16 |
	 * |  2  |  9  |  1  |                       32 |                          32 |                8 |
	 * |  2  | 10  |  1  |                       32 |                          32 |               16 |
	 * +-----+-----+-----+--------------------------+-----------------------------+------------------+
	 * which leaves us with two structures and a meta-function to know which structure to use.
	 * If/when we add more KWAs or MALs, this may change, but the structure will always only depend on those two 
	 * parameters, at least according to my current proposal, as proposed on the SATF mailing list on June 29.
	 */

	struct WrappedKeyDataE0T8
	{
		unsigned char control_direction_authentication_key_[32];
		unsigned char monitoring_direction_authentication_key_[32];
		unsigned char mac_value_[8];
	};
    static_assert(sizeof(WrappedKeyDataE0T8) == 72, "unexpected padding");
	struct WrappedKeyDataE0T16
	{
		unsigned char control_direction_authentication_key_[32];
		unsigned char monitoring_direction_authentication_key_[32];
		unsigned char mac_value_[16];
	};
    static_assert(sizeof(WrappedKeyDataE0T16) == 80, "unexpected padding");
	struct WrappedKeyDataE1T8
	{
		unsigned char control_direction_authentication_key_[32];
		unsigned char monitoring_direction_authentication_key_[32];
		unsigned char control_direction_encryption_key_[32];
		unsigned char monitoring_direction_encryption_key_[32];
		unsigned char mac_value_[8];
	};
    static_assert(sizeof(WrappedKeyDataE1T8) == 136, "unexpected padding");
	struct WrappedKeyDataE1T16
	{
		unsigned char control_direction_authentication_key_[32];
		unsigned char monitoring_direction_authentication_key_[32];
		unsigned char control_direction_encryption_key_[32];
		unsigned char monitoring_direction_encryption_key_[32];
		unsigned char mac_value_[16];
	};
    static_assert(sizeof(WrappedKeyDataE1T16) == 144, "unexpected padding");
	template < KeyWrapAlgorithm kwa, MACAlgorithm mal, EncryptionAlgorithm eal >
	struct WrappedKeyData;
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_8__	, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_16__	, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T16 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_8__	, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_16__, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T16 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_8__	, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_16__	, EncryptionAlgorithm::null__       >	{ typedef WrappedKeyDataE0T16 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_8__	, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_16__	, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T16 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_8__	, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_16__, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T16 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_8__	, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T8 type;	};
	template < > struct WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_16__	, EncryptionAlgorithm::aes256_cbc__ >	{ typedef WrappedKeyDataE1T16 type;	};

	void wrap(
          boost::asio::mutable_buffer &out
        , boost::asio::const_buffer const &update_key
        , KeyWrapAlgorithm kwa
        , MACAlgorithm mal
        , EncryptionAlgorithm eal
        , boost::asio::const_buffer const &control_direction_authentication_key
        , boost::asio::const_buffer const &monitoring_direction_authentication_key
        , boost::asio::const_buffer const &control_direction_encryption_key
        , boost::asio::const_buffer const &monitoring_direction_encryption_key
        , boost::asio::const_buffer const &mac_value
        );
    bool unwrap(
          boost::asio::mutable_buffer &control_direction_authentication_key
        , boost::asio::mutable_buffer &monitoring_direction_authentication_key
        , boost::asio::mutable_buffer &control_direction_encryption_key
        , boost::asio::mutable_buffer &monitoring_direction_encryption_key
        , boost::asio::mutable_buffer &mac_value
        , unsigned int &mac_value_size
        , boost::asio::const_buffer const& update_key
        , KeyWrapAlgorithm kwa
        , MACAlgorithm mal
        , EncryptionAlgorithm eal
        , boost::asio::const_buffer const& incoming_wrapped_key_data
        );
}

#endif

