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
#include "aeadalgorithm.hpp"
#include <stdexcept>

namespace DNP3SAv6 {
    unsigned int getMACAlgorithmDigestSize(AEADAlgorithm mac_algorithm)
	{
        switch (mac_algorithm)
	    {
        case AEADAlgorithm::hmac_sha_256_truncated_8__     :
        case AEADAlgorithm::hmac_sha_3_256_truncated_8__   :
        case AEADAlgorithm::hmac_blake2s_truncated_8__     :
            return 8;
        case AEADAlgorithm::hmac_sha_256_truncated_16__    :
        case AEADAlgorithm::hmac_sha_3_256_truncated_16__  :
        case AEADAlgorithm::hmac_blake2s_truncated_16__    :
            return 16;
        default :
            throw std::logic_error("Unknown MAC algorithm type");
	    }
    }
}
