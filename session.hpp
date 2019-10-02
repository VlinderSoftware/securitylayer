#ifndef dnp3sav6_session_hpp
#define dnp3sav6_session_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <cstdint>

namespace DNP3SAv6 { 
struct Session
{
	unsigned char control_direction_session_key_[32];
	unsigned char monitoring_direction_session_key_[32];
};
}
#endif

