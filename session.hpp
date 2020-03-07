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
#ifndef dnp3sav6_session_hpp
#define dnp3sav6_session_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "keywrapalgorithm.hpp"
#include "aeadalgorithm.hpp"
#include "config.hpp"
#include "details/direction.hpp"
#include <boost/asio.hpp>

namespace DNP3SAv6 { 
class SessionBuilder;
class Session
{
public :
    Session(boost::asio::io_context &ioc);
    Session(Session const &other);
    Session(Session &&other) = default;

    Session& operator=(Session const &other);
    Session& operator=(Session &&other) = default;

    KeyWrapAlgorithm getKeyWrapAlgorithm() const noexcept;
    AEADAlgorithm getAEADAlgorithm() const noexcept;

    boost::asio::const_buffer getControlDirectionSessionKey() const noexcept;
    boost::asio::const_buffer getMonitoringDirectionSessionKey() const noexcept;

    bool valid(Details::Direction direction) const noexcept;
    void reset() noexcept;

protected :
    void start(std::chrono::seconds const &ttl_duration, unsigned int session_key_change_count);

private :
	KeyWrapAlgorithm key_wrap_algorithm_ = KeyWrapAlgorithm::unknown__;
	AEADAlgorithm aead_algorithm_ = AEADAlgorithm::unknown__;

    unsigned char control_direction_session_key_[Config::max_session_key_size__];
    std::size_t control_direction_session_key_size_ = 0;
	unsigned char monitoring_direction_session_key_[Config::max_session_key_size__];
    std::size_t monitoring_direction_session_key_size_ = 0;

    bool valid_ = false;
    mutable unsigned int control_direction_session_key_use_count_ = 0;
    mutable unsigned int monitoring_direction_session_key_use_count_ = 0;

	boost::asio::steady_timer session_timeout_;
	unsigned int session_key_change_count_ = 0;
    boost::asio::io_context *io_context_;

    friend class SessionBuilder;
};
}
#endif

