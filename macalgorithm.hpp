#ifndef dnp3sav6_macalgorithm_hpp
#define dnp3sav6_macalgorithm_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <cstdint>

namespace DNP3SAv6 {
	enum struct MACAlgorithm : std::uint8_t
	{
		  hmac_sha_256_truncated_8__ = 3
		, hmac_sha_256_truncated_16__ = 4
		, hmac_sha_256__ = 7
		, hmac_blake2s_truncated_8__ = 8
		, hmac_blake2s_truncated_16__ = 9
		, hmac_blake2s__ = 10
		//TODO add SHA-3-based algorithms
	};
}

#endif



