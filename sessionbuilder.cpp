#include "sessionbuilder.hpp"
#include "sessionbuilder.hpp"
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
#include "sessionbuilder.hpp"
#include "exceptions/contract.hpp"
#include "details/irandomnumbergenerator.hpp"
#include "hmac.hpp"
#include "messages/wrappedkeydata.hpp"
#include <openssl/crypto.h>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
	SessionBuilder::SessionBuilder(boost::asio::io_context &ioc, Details::IRandomNumberGenerator &random_number_generator, Config const &config)
		: Session(ioc)
		, random_number_generator_(random_number_generator)
        , config_(config)
	{
        pre_condition(config.session_key_change_count_ <= OPTION_MAX_SESSION_KEY_CHANGE_COUNT);
	}

	void SessionBuilder::reset() noexcept
	{
		Session::reset();
		session_start_request_message_size_ = 0;
		session_start_response_message_size_ = 0;
		session_start_response_nonce_size_ = 0;
		session_key_change_request_message_size_ = 0;
	}

	Session SessionBuilder::getSession() const noexcept
	{
		Session session(*this);
		session.start(std::chrono::seconds(config_.session_key_change_interval_), config_.session_key_change_count_);
		return session;
	}

	void SessionBuilder::setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm)
	{
		pre_condition(key_wrap_algorithm != KeyWrapAlgorithm::unknown__);
		key_wrap_algorithm_ = key_wrap_algorithm;
	}

	void SessionBuilder::setMACAlgorithm(AEADAlgorithm aead_algorithm)
	{
		pre_condition(aead_algorithm != AEADAlgorithm::unknown__);
		aead_algorithm_ = aead_algorithm;
	}

	void SessionBuilder::setSessionStartRequest(const_buffer const &spdu)
	{
		pre_condition(spdu.size() <= sizeof(session_start_request_message_));
		memcpy(session_start_request_message_, spdu.data(), spdu.size());
		session_start_request_message_size_ = spdu.size();
	}
	void SessionBuilder::setSessionStartResponse(const_buffer const &spdu, const_buffer const &nonce)
	{
		pre_condition(spdu.size() <= sizeof(session_start_request_message_));
		pre_condition(nonce.size() <= sizeof(session_start_response_nonce_));
		memcpy(session_start_response_message_, spdu.data(), spdu.size());
		session_start_response_message_size_ = spdu.size();
		memcpy(session_start_response_nonce_, nonce.data(), nonce.size());
		session_start_response_nonce_size_ = nonce.size();
	}

    void SessionBuilder::setSessionKeyChangeRequest(boost::asio::const_buffer const& spdu)
    {
		pre_condition(spdu.size() <= sizeof(session_key_change_request_message_));
		memcpy(session_key_change_request_message_, spdu.data(), spdu.size());
		session_key_change_request_message_size_ = spdu.size();
    }

    unsigned int SessionBuilder::getWrappedKeyDataLength() const
    {
	    switch (static_cast< KeyWrapAlgorithm >(config_.key_wrap_algorithm_))
	    {
	    case KeyWrapAlgorithm::rfc3394_aes256_key_wrap__ :
		    switch (static_cast< AEADAlgorithm >(config_.aead_algorithm_))
		    {
		    case AEADAlgorithm::hmac_sha_256_truncated_8__		: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_8__       >::type) + 8/*IV size*/;
		    case AEADAlgorithm::hmac_sha_256_truncated_16__		: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_16__      >::type) + 8/*IV size*/;
            case AEADAlgorithm::hmac_sha_3_256_truncated_8__	: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_8__     >::type) + 8/*IV size*/;
		    case AEADAlgorithm::hmac_sha_3_256_truncated_16__	: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_16__    >::type) + 8/*IV size*/;
		    case AEADAlgorithm::hmac_blake2s_truncated_8__		: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_8__       >::type) + 8/*IV size*/;
		    case AEADAlgorithm::hmac_blake2s_truncated_16__		: return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_16__      >::type) + 8/*IV size*/;
		    case AEADAlgorithm::aes256_gcm__		            : return sizeof(typename Messages::WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::aes256_gcm__                     >::type) + 8/*IV size*/;
		    default : 
			    throw std::logic_error("Unknown MAC algorithm");
		    }
            break;
	    default :
		    throw std::logic_error("Unknown key-wrap algorithm");
	    }
    }

    mutable_buffer SessionBuilder::createWrappedKeyData(mutable_buffer buffer)
	{
		using Messages::wrap;

		key_wrap_algorithm_ = static_cast< decltype(key_wrap_algorithm_) >(config_.key_wrap_algorithm_);
		aead_algorithm_ = static_cast< decltype(aead_algorithm_) >(config_.aead_algorithm_);

		unsigned char *curr(static_cast< unsigned char* >(buffer.data()));
		unsigned char *const end(curr + buffer.size());

		mutable_buffer control_direction_session_key_buffer(control_direction_session_key_, sizeof(control_direction_session_key_));
		random_number_generator_.generate(control_direction_session_key_buffer);
		control_direction_session_key_size_ = sizeof(control_direction_session_key_);

		mutable_buffer monitoring_direction_session_key_buffer(monitoring_direction_session_key_, sizeof(monitoring_direction_session_key_));
		random_number_generator_.generate(monitoring_direction_session_key_buffer);
		monitoring_direction_session_key_size_ = sizeof(monitoring_direction_session_key_);
		// encode it all into the mutable buffer
		wrap(
			  buffer
			, getUpdateKey()
			, key_wrap_algorithm_
			, aead_algorithm_
			, const_buffer(control_direction_session_key_, sizeof(control_direction_session_key_))
			, const_buffer(monitoring_direction_session_key_, sizeof(monitoring_direction_session_key_))
			, getDigest(Details::Direction::control__)
			);
		valid_ = true;

		return buffer;
	}

	bool SessionBuilder::unwrapKeyData(boost::asio::const_buffer const& incoming_key_wrap_data)
	{
		using Messages::unwrap;

		pre_condition(key_wrap_algorithm_ != KeyWrapAlgorithm::unknown__);
		pre_condition(aead_algorithm_ != AEADAlgorithm::unknown__);

		pre_condition(incoming_key_wrap_data.size() <= Config::max_key_wrap_data_size__);

		// calculate the MAC over the first two messages using the control direction session key
		unsigned char incoming_control_direction_session_key[sizeof(control_direction_session_key_)];
		unsigned char incoming_monitoring_direction_session_key[sizeof(monitoring_direction_session_key_)];
		unsigned char incoming_digest_value[Config::max_digest_size__];
		unsigned int incoming_digest_value_size(0);

		mutable_buffer incoming_control_direction_session_key_buffer(incoming_control_direction_session_key, sizeof(incoming_control_direction_session_key));
		mutable_buffer incoming_monitoring_direction_session_key_buffer(incoming_monitoring_direction_session_key, sizeof(incoming_monitoring_direction_session_key));
		mutable_buffer incoming_digest_value_buffer(incoming_digest_value, sizeof(incoming_digest_value));
		if (unwrap(
			  incoming_control_direction_session_key_buffer
			, incoming_monitoring_direction_session_key_buffer
			, incoming_digest_value_buffer
			, incoming_digest_value_size
			, getUpdateKey()
			, key_wrap_algorithm_
			, aead_algorithm_
			, incoming_key_wrap_data
			))
		{
			// the incoming digest value size is determined by the algorithm used, so we don't need to check it at run-time (though we assert to make sure our buffer is big enough here)
			assert(incoming_digest_value_size <= sizeof(incoming_digest_value));

			unsigned char expected_digest[Config::max_digest_size__];
			mutable_buffer expected_digest_buffer(expected_digest, sizeof(expected_digest));
			auto expected_digest_value(
				  getDigest(
					  expected_digest_buffer
					, const_buffer(
						  incoming_control_direction_session_key
						, sizeof(incoming_control_direction_session_key)
						)
					)
				);

			assert(expected_digest_value.size() >= incoming_digest_value_size);
			if (CRYPTO_memcmp(expected_digest_value.data(), incoming_digest_value, incoming_digest_value_size) == 0)
			{
				static_assert(sizeof(control_direction_session_key_) == sizeof(incoming_control_direction_session_key), "unexpected size mismatch");
				memcpy(control_direction_session_key_, incoming_control_direction_session_key, sizeof(incoming_control_direction_session_key));
				control_direction_session_key_size_ = sizeof(incoming_control_direction_session_key);
				static_assert(sizeof(monitoring_direction_session_key_) == sizeof(incoming_monitoring_direction_session_key), "unexpected size mismatch");
				memcpy(monitoring_direction_session_key_, incoming_monitoring_direction_session_key, sizeof(incoming_monitoring_direction_session_key));
				monitoring_direction_session_key_size_ = sizeof(incoming_monitoring_direction_session_key);
				valid_ = true;
				return true;
			}
			else
			{ //TODO stats and somesuch
			}
		}
		else
		{ //TODO stats and somesuch
		}

		return false;
	}

	boost::asio::const_buffer SessionBuilder::getUpdateKey() const
	{   //TODO get this from somewhere
		static unsigned char const update_key__[] = {
			  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
			, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
			};
		return const_buffer(update_key__, sizeof(update_key__));
	}

	boost::asio::const_buffer SessionBuilder::getDigest(Details::Direction direction) const noexcept
	{
		if (direction == Details::Direction::control__)
		{
			mutable_buffer control_direction_digest_buffer(control_direction_digest_, sizeof(control_direction_digest_));
			return getDigest(
				  control_direction_digest_buffer
				, const_buffer(control_direction_session_key_, sizeof(control_direction_session_key_))
				);
		}
		else
		{
			pre_condition(direction == Details::Direction::monitoring__);
			mutable_buffer monitoring_direction_digest_buffer(monitoring_direction_digest_, sizeof(monitoring_direction_digest_));
			return getDigest(
				  monitoring_direction_digest_buffer
				, const_buffer(monitoring_direction_session_key_, sizeof(monitoring_direction_session_key_))
				);
		}
	}

	std::uint32_t SessionBuilder::getSEQ() const noexcept
	{
		return seq_;
	}

	void SessionBuilder::setSEQ(std::uint32_t seq) noexcept
	{
		seq_ = seq;
	}

	boost::asio::const_buffer SessionBuilder::getDigest(boost::asio::mutable_buffer &out_digest, boost::asio::const_buffer const &session_key) const noexcept
	{
		digest(
			  out_digest
			, aead_algorithm_
			, session_key
			, const_buffer(session_start_request_message_, session_start_request_message_size_)
			, const_buffer(session_start_response_message_, session_start_response_message_size_)
			, const_buffer(session_key_change_request_message_, session_key_change_request_message_size_)
			);
		return out_digest;
	}
}




