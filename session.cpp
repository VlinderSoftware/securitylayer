#include "session.hpp"

namespace DNP3SAv6 { 
KeyWrapAlgorithm Session::getKeyWrapAlgorithm() const noexcept
{
    return key_wrap_algorithm_;
}

MACAlgorithm Session::getMACAlgorithm() const noexcept
{
    return mac_algorithm_;
}

boost::asio::const_buffer Session::getControlDirectionSessionKey() const noexcept
{
    return boost::asio::const_buffer(control_direction_session_key_, control_direction_session_key_size_);
}

boost::asio::const_buffer Session::getMonitoringDirectionSessionKey() const noexcept
{
    return boost::asio::const_buffer(monitoring_direction_session_key_, monitoring_direction_session_key_size_);
}

bool Session::valid() const noexcept
{
    return valid_;
}

void Session::reset() noexcept
{
    *this = Session();
}

}
