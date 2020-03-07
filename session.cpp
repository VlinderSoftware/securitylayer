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
#include "session.hpp"

using namespace std;

namespace DNP3SAv6 {
Session::Session(boost::asio::io_context& ioc)
    : io_context_(&ioc)
    , session_timeout_(ioc)
{ /* no-op */ }
Session::Session(Session const &other)
	: key_wrap_algorithm_(other.key_wrap_algorithm_)
	, aead_algorithm_(other.aead_algorithm_)
    , control_direction_session_key_size_(other.control_direction_session_key_size_)
    , monitoring_direction_session_key_size_(other.monitoring_direction_session_key_size_)
    , valid_(other.valid_)
    , control_direction_session_key_use_count_(other.control_direction_session_key_use_count_)
    , monitoring_direction_session_key_use_count_(other.monitoring_direction_session_key_use_count_)
	, session_timeout_(*other.io_context_)
	, session_key_change_count_(other.session_key_change_count_)
    , io_context_(other.io_context_)
{
    copy(begin(other.control_direction_session_key_), end(other.control_direction_session_key_), begin(control_direction_session_key_));
	copy(begin(other.monitoring_direction_session_key_), end(other.monitoring_direction_session_key_), begin(monitoring_direction_session_key_));
    session_timeout_.expires_at(other.session_timeout_.expires_at());
}

Session& Session::operator=(Session const &other)
{
    Session temp(other);
    return *this = std::move(temp);
}

KeyWrapAlgorithm Session::getKeyWrapAlgorithm() const noexcept
{
    return key_wrap_algorithm_;
}

AEADAlgorithm Session::getAEADAlgorithm() const noexcept
{
    return aead_algorithm_;
}

boost::asio::const_buffer Session::getControlDirectionSessionKey() const noexcept
{
    if (!valid(Details::Direction::control__))
    {
        return boost::asio::const_buffer();
    }
    else
    { /* still valid */ }
    ++control_direction_session_key_use_count_;
    return boost::asio::const_buffer(control_direction_session_key_, control_direction_session_key_size_);
}

boost::asio::const_buffer Session::getMonitoringDirectionSessionKey() const noexcept
{
    if (!valid(Details::Direction::monitoring__))
    {
        return boost::asio::const_buffer();
    }
    else
    { /* still valid */ }
    ++monitoring_direction_session_key_use_count_;
    return boost::asio::const_buffer(monitoring_direction_session_key_, monitoring_direction_session_key_size_);
}

bool Session::valid(Details::Direction direction) const noexcept
{
    auto const relevant_use_count((direction == Details::Direction::control__) ? control_direction_session_key_use_count_ : monitoring_direction_session_key_use_count_);
    return true
        && valid_
        && (relevant_use_count < session_key_change_count_)
        && (session_timeout_.expires_from_now().count() > 0)
        ;
}

void Session::reset() noexcept
{
    *this = Session(*io_context_);
}

void Session::start(std::chrono::seconds const& ttl_duration, unsigned int session_key_change_count)
{
    session_key_change_count_ = session_key_change_count;
    session_timeout_.expires_from_now(ttl_duration);
}

}
