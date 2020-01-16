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
#ifndef dnp3sav6_aead_hpp
#define dnp3sav6_aead_hpp
/* Our implementation of an RFC 5116 AEAD interface.
 * As per section 2.1, encryption has four inputs: a key, a nonce, a plaintext and associated data. Because we don't 
 * expect all the plaintext data to necessarily be in a single buffer, but we do expect the keym the nonce and the 
 * associated data to be available in a single buffer each, our variadic template ends with buffers for the data.
 * This is similar to our HMAC interface, which is used by the session builder to build an HMAC over the first two 
 * messages of the handshake. */

#include "details/aeadhmacadapter.hpp"
#include "details/hmacblake2s.hpp"
#include "details/hmacsha256.hpp"
#include "details/hmacsha3256.hpp"
#include "details/aesgcm.hpp"
#include "exceptions/contract.hpp"
#include "aeadalgorithm.hpp"
#include <algorithm>

namespace DNP3SAv6 {

	template < AEADAlgorithm a__ > struct AEADType;
	template <> struct AEADType< AEADAlgorithm::hmac_sha_256_truncated_8__      > { typedef Details::AEADHMACAdapter< Details::HMACSHA256,  AEADAlgorithm::hmac_sha_256_truncated_8__    > type; };
	template <> struct AEADType< AEADAlgorithm::hmac_sha_256_truncated_16__     > { typedef Details::AEADHMACAdapter< Details::HMACSHA256,  AEADAlgorithm::hmac_sha_256_truncated_16__   > type; };
	template <> struct AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_8__    > { typedef Details::AEADHMACAdapter< Details::HMACSHA3256, AEADAlgorithm::hmac_sha_3_256_truncated_8__  > type; };
	template <> struct AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_16__   > { typedef Details::AEADHMACAdapter< Details::HMACSHA3256, AEADAlgorithm::hmac_sha_3_256_truncated_16__ > type; };
	template <> struct AEADType< AEADAlgorithm::hmac_blake2s_truncated_8__      > { typedef Details::AEADHMACAdapter< Details::HMACBLAKE2s, AEADAlgorithm::hmac_blake2s_truncated_8__    > type; };
	template <> struct AEADType< AEADAlgorithm::hmac_blake2s_truncated_16__     > { typedef Details::AEADHMACAdapter< Details::HMACBLAKE2s, AEADAlgorithm::hmac_blake2s_truncated_16__   > type; };
	template <> struct AEADType< AEADAlgorithm::aes256_gcm__                    > { typedef Details::AESGCM                                                                                type; };

	void encrypt_(Details::IAEAD &aead, boost::asio::const_buffer const &data);

	template < typename... Buffers >
	void encrypt_(Details::IAEAD &aead, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		encrypt_(aead, data);
		encrypt_(aead, additional_buffers...);
	}
	template < typename... Buffers >
	boost::asio::const_buffer encrypt(Details::IAEAD &&aead, Buffers... data)
	{
		encrypt_(aead, data...);
		return aead.getEncrypted();
	}

	template < typename... Buffers >
	boost::asio::const_buffer encrypt(boost::asio::mutable_buffer out, AEADAlgorithm algorithm, boost::asio::const_buffer const &key, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &associated_data, Buffers... data)
	{
		switch (algorithm)
		{
		case AEADAlgorithm::hmac_sha_256_truncated_8__      : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_256_truncated_8__     >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::hmac_sha_256_truncated_16__     : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_256_truncated_16__    >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_8__    : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_8__   >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_16__   : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_16__  >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::hmac_blake2s_truncated_8__      : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_blake2s_truncated_8__     >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::hmac_blake2s_truncated_16__     : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_blake2s_truncated_16__    >::type >(out, key, nonce, associated_data), data...); break;
		case AEADAlgorithm::aes256_gcm__                    : return encrypt(Details::makeAEAD< AEADType< AEADAlgorithm::aes256_gcm__                   >::type >(out, key, nonce, associated_data), data...); break;
		default : throw std::logic_error("Unexpected algorithm value");
		};
	}

	void decrypt_(Details::IAEAD &aead, boost::asio::const_buffer const &data);
	template < typename... Buffers >
	void decrypt_(Details::IAEAD &aead, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		decrypt_(aead, data);
		decrypt_(aead, additional_buffers...);
	}
	template < typename... Buffers >
	boost::asio::const_buffer decrypt(Details::IAEAD &&aead, Buffers... data)
	{
		decrypt_(aead, data...);
		return aead.getDecrypted();
	}

    template < typename... Buffers >
    boost::asio::const_buffer decrypt(boost::asio::mutable_buffer out, AEADAlgorithm algorithm, boost::asio::const_buffer const &key, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &associated_data, Buffers... encrypted_data)
    {
		switch (algorithm)
		{
		case AEADAlgorithm::hmac_sha_256_truncated_8__      : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_256_truncated_8__     >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::hmac_sha_256_truncated_16__     : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_256_truncated_16__    >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_8__    : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_8__   >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_16__   : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_sha_3_256_truncated_16__  >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::hmac_blake2s_truncated_8__      : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_blake2s_truncated_8__     >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::hmac_blake2s_truncated_16__     : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::hmac_blake2s_truncated_16__    >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		case AEADAlgorithm::aes256_gcm__                    : return decrypt(Details::makeAEAD< AEADType< AEADAlgorithm::aes256_gcm__                   >::type >(out, key, nonce, associated_data), encrypted_data...); break;
		default : throw std::logic_error("Unexpected algorithm value");
		};
    }
}

#endif
