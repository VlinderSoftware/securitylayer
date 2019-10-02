#ifndef dnp3sav6_keywrapalgorithm_hpp
#define dnp3sav6_keywrapalgorithm_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <cstdint>

namespace DNP3SAv6 {
	enum struct KeyWrapAlgorithm : std::uint8_t
	{
          unknown__                 = 0 // not a valid over-the-wire value
		// key wrap as defined by NIST SP800-38F using AES-256 in GCM mode.
		, rfc3394_aes256_key_wrap__ = 2
	};
}

#endif



