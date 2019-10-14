#ifndef dnp3sav6_session_hpp
#define dnp3sav6_session_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"
#include "config.hpp"
#include <boost/asio/buffer.hpp>

namespace DNP3SAv6 { 
class SessionBuilder;
class Session
{
public :
    KeyWrapAlgorithm getKeyWrapAlgorithm() const noexcept;
    MACAlgorithm getMACAlgorithm() const noexcept;

    boost::asio::const_buffer getControlDirectionSessionKey() const noexcept;
    boost::asio::const_buffer getMonitoringDirectionSessionKey() const noexcept;

    bool valid() const noexcept;
    void reset() noexcept;

private :
	KeyWrapAlgorithm key_wrap_algorithm_ = KeyWrapAlgorithm::unknown__;
	MACAlgorithm mac_algorithm_ = MACAlgorithm::unknown__;

    unsigned char control_direction_session_key_[Config::max_session_key_size__];
    std::size_t control_direction_session_key_size_ = 0;
	unsigned char monitoring_direction_session_key_[Config::max_session_key_size__];
    std::size_t monitoring_direction_session_key_size_ = 0;

    bool valid_ = false;

    friend class SessionBuilder;
};
}
#endif

