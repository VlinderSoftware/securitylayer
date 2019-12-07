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
#ifndef dnp3sav6_sessionbuilder_hpp
#define dnp3sav6_sessionbuilder_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "config.hpp"
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"
#include "session.hpp"
#include <boost/asio.hpp>

namespace DNP3SAv6 {
namespace Details {
	class IRandomNumberGenerator;
}
class SessionBuilder : private Session
{
public :
    enum struct Direction {
          control_direction__
        , monitoring_direction__
        };

	SessionBuilder(boost::asio::io_context &ioc, Details::IRandomNumberGenerator &random_number_generator);
	~SessionBuilder() = default;
	
	SessionBuilder(SessionBuilder &&other) noexcept = default;
	SessionBuilder& operator=(SessionBuilder &&other) noexcept = default;
	SessionBuilder(SessionBuilder const&) = delete;
	SessionBuilder& operator=(SessionBuilder const&) = delete;

	void reset() noexcept;

    Session getSession() const noexcept;

	void setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm);
	void setMACAlgorithm(MACAlgorithm mac_algorithm);
    void setEncryptionAlgorithm(EncryptionAlgorithm encryption_algorithm);

	// whole messages to calculate a MAC over
	void setSessionStartRequest(boost::asio::const_buffer const &spdu);
	void setSessionStartResponse(boost::asio::const_buffer const &spdu, boost::asio::const_buffer const &nonce);

	void setSessionKeyChangeInterval(std::chrono::seconds const &ttl_duration);
	void setSessionKeyChangeCount(unsigned int session_key_change_count);

	boost::asio::mutable_buffer createWrappedKeyData(boost::asio::mutable_buffer buffer);
    bool unwrapKeyData(boost::asio::const_buffer const& incoming_key_wrap_data);

    boost::asio::const_buffer getUpdateKey() const;

    using Session::getKeyWrapAlgorithm;
    using Session::getMACAlgorithm;

    boost::asio::const_buffer getDigest(Direction direction) const noexcept;

    std::uint32_t getSEQ() const noexcept;
    void setSEQ(std::uint32_t seq) noexcept;

private :
    boost::asio::const_buffer getDigest(boost::asio::mutable_buffer &out_digest, boost::asio::const_buffer const &authentication_key) const noexcept;
    
	unsigned char session_start_request_message_[Config::max_spdu_size__];
	unsigned int session_start_request_message_size_ = 0;
	unsigned char session_start_response_message_[Config::max_spdu_size__];
	unsigned int session_start_response_message_size_ = 0;
	unsigned char session_start_response_nonce_[Config::max_spdu_size__];
	unsigned int session_start_response_nonce_size_ = 0;

	boost::asio::steady_timer session_timeout_;
	unsigned int session_key_change_count_ = 0;

	Details::IRandomNumberGenerator &random_number_generator_;

    mutable unsigned char control_direction_digest_[Config::max_digest_size__];
    mutable unsigned char monitoring_direction_digest_[Config::max_digest_size__];

    std::uint32_t seq_;
};
}

#endif
