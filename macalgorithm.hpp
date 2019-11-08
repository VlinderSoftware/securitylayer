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
#ifndef dnp3sav6_macalgorithm_hpp
#define dnp3sav6_macalgorithm_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <cstdint>

namespace DNP3SAv6 {
	enum struct MACAlgorithm : std::uint8_t
	{
          unknown__                     = 0 // not a valid over-the-wire value
		, hmac_sha_256_truncated_8__	= 3
		, hmac_sha_256_truncated_16__	= 4
		, hmac_sha_3_256_truncated_8__	= 7
		, hmac_sha_3_256_truncated_16__ = 8
		, hmac_blake2s_truncated_8__	= 9
		, hmac_blake2s_truncated_16__	= 10
	};
    unsigned int getMACAlgorithmDigestSize(MACAlgorithm mac_algorithm);
}

#endif



