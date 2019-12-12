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
#include "macalgorithm.hpp"
#include "encryptionalgorithm.hpp"
#include "config.hpp"
#include <boost/asio/buffer.hpp>
#include <memory>

namespace DNP3SAv6 { 
class SessionBuilder;
class IEncryption;
class Session
{
public :
    Session() = default;
    ~Session() = default;

    Session(Session const&) = default;
    Session& operator=(Session const&) = default;
    Session(Session &&) = default;
    Session& operator=(Session &&) = default;

    KeyWrapAlgorithm getKeyWrapAlgorithm() const noexcept;
    MACAlgorithm getMACAlgorithm() const noexcept;

    boost::asio::const_buffer getControlDirectionSessionKey() const noexcept;
    boost::asio::const_buffer getMonitoringDirectionSessionKey() const noexcept;

    std::shared_ptr< IEncryption > getControlDirectionEncryption() const noexcept { return control_direction_encryption_; }
    std::shared_ptr< IEncryption > getMonitoringDirectionEncryption() const noexcept { return monitoring_direction_encryption_; }

    bool valid() const noexcept;
    void reset() noexcept;

private :
	KeyWrapAlgorithm key_wrap_algorithm_ = KeyWrapAlgorithm::unknown__;
	MACAlgorithm mac_algorithm_ = MACAlgorithm::unknown__;
    EncryptionAlgorithm encryption_algorithm_ = EncryptionAlgorithm::unknown__;

    unsigned char control_direction_authentication_key_[Config::max_session_key_size__];
    std::size_t control_direction_authentication_key_size_ = 0;
	unsigned char monitoring_direction_authentication_key_[Config::max_session_key_size__];
    std::size_t monitoring_direction_authentication_key_size_ = 0;
    unsigned char control_direction_encryption_key_[Config::max_session_key_size__];
    std::size_t control_direction_encryption_key_size_ = 0;
	unsigned char monitoring_direction_encryption_key_[Config::max_session_key_size__];
    std::size_t monitoring_direction_encryption_key_size_ = 0;
    std::shared_ptr< IEncryption > control_direction_encryption_;
    std::shared_ptr< IEncryption > monitoring_direction_encryption_;

    bool valid_ = false;

    friend class SessionBuilder;
};
}
#endif

