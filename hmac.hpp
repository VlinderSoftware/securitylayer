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
#ifndef dnp3sav6_hmac_hpp
#define dnp3sav6_hmac_hpp

#include "details/hmacblake2s.hpp"
#include "details/hmacsha256.hpp"
#include "details/hmacsha3256.hpp"
#include "exceptions/contract.hpp"
#include "macalgorithm.hpp"
#include <algorithm>

#ifdef min
#undef min
#endif

using namespace std;

namespace DNP3SAv6 {

	template < MACAlgorithm a__ > struct HMACType;
	template <> struct HMACType< MACAlgorithm::hmac_sha_256_truncated_8__    > { typedef Details::HMACSHA256 type; };
	template <> struct HMACType< MACAlgorithm::hmac_sha_256_truncated_16__   > { typedef Details::HMACSHA256 type; };
	template <> struct HMACType< MACAlgorithm::hmac_sha_3_256_truncated_8__  > { typedef Details::HMACSHA3256 type; };
	template <> struct HMACType< MACAlgorithm::hmac_sha_3_256_truncated_16__ > { typedef Details::HMACSHA3256 type; };
	template <> struct HMACType< MACAlgorithm::hmac_blake2s_truncated_8__    > { typedef Details::HMACBLAKE2s type; };
	template <> struct HMACType< MACAlgorithm::hmac_blake2s_truncated_16__   > { typedef Details::HMACBLAKE2s type; };

	void digest_(Details::IHMAC &hmac, boost::asio::const_buffer const &data);

	template < typename... Buffers >
	void digest_(Details::IHMAC &hmac, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		digest_(hmac, data);
		digest_(hmac, additional_buffers...);
	}
	template < typename... Buffers >
	void digest(Details::IHMAC &&hmac, boost::asio::mutable_buffer out, boost::asio::const_buffer const &key, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		pre_condition(out.data() || !out.size());
		hmac.setKey(key);
		digest_(hmac, data, additional_buffers...);
		auto digested(hmac.get());
		size_t to_copy(min(out.size(), digested.size()));
		memcpy(out.data(), digested.data(), to_copy);
	}

	template < typename... Buffers >
	void digest(boost::asio::mutable_buffer out, MACAlgorithm algorithm, boost::asio::const_buffer const &key, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		switch (algorithm)
		{
		case MACAlgorithm::hmac_sha_256_truncated_8__    : digest(HMACType< MACAlgorithm::hmac_sha_256_truncated_8__    >::type(), out, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_256_truncated_16__   : digest(HMACType< MACAlgorithm::hmac_sha_256_truncated_16__   >::type(), out, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_8__  : digest(HMACType< MACAlgorithm::hmac_sha_3_256_truncated_8__  >::type(), out, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_16__ : digest(HMACType< MACAlgorithm::hmac_sha_3_256_truncated_16__ >::type(), out, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_blake2s_truncated_8__    : digest(HMACType< MACAlgorithm::hmac_blake2s_truncated_8__    >::type(), out, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_blake2s_truncated_16__   : digest(HMACType< MACAlgorithm::hmac_blake2s_truncated_16__   >::type(), out, key, data, additional_buffers...); break;
		default : throw std::logic_error("Unexpected algorithm value");
		};
	}

	template < typename... Buffers >
	bool verify(Details::IHMAC &hmac, boost::asio::const_buffer const &incoming_digest, boost::asio::const_buffer const &key, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		hmac.setKey(key);
		digest_(hmac, data, additional_buffers...);
		return hmac.verify(incoming_digest);
	}

	template < typename... Buffers >
	bool verify(boost::asio::const_buffer const &incoming_digest, MACAlgorithm algorithm, boost::asio::const_buffer const &key, boost::asio::const_buffer const &data, Buffers... additional_buffers)
	{
		switch (algorithm)
		{
		case MACAlgorithm::hmac_sha_256_truncated_8__    : return verify(HMACType< MACAlgorithm::hmac_sha_256_truncated_8__    >::type(), incoming_digest, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_256_truncated_16__   : return verify(HMACType< MACAlgorithm::hmac_sha_256_truncated_16__   >::type(), incoming_digest, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_8__  : return verify(HMACType< MACAlgorithm::hmac_sha_3_256_truncated_8__  >::type(), incoming_digest, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_16__ : return verify(HMACType< MACAlgorithm::hmac_sha_3_256_truncated_16__ >::type(), incoming_digest, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_blake2s_truncated_8__    : return verify(HMACType< MACAlgorithm::hmac_blake2s_truncated_8__    >::type(), incoming_digest, key, data, additional_buffers...); break;
		case MACAlgorithm::hmac_blake2s_truncated_16__   : return verify(HMACType< MACAlgorithm::hmac_blake2s_truncated_16__   >::type(), incoming_digest, key, data, additional_buffers...); break;
		default : throw std::logic_error("Unexpected algorithm value");
		};
	}
}

#endif
