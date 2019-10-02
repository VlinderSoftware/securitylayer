#include "macalgorithm.hpp"
#include <stdexcept>

namespace DNP3SAv6 {
    unsigned int getMACAlgorithmDigestSize(MACAlgorithm mac_algorithm)
	{
        switch (mac_algorithm)
	    {
        case MACAlgorithm::hmac_sha_256_truncated_8__     :
        case MACAlgorithm::hmac_sha_3_256_truncated_8__   :
        case MACAlgorithm::hmac_blake2s_truncated_8__     :
            return 8;
        case MACAlgorithm::hmac_sha_256_truncated_16__    :
        case MACAlgorithm::hmac_sha_3_256_truncated_16__  :
        case MACAlgorithm::hmac_blake2s_truncated_16__    :
            return 16;
        default :
            throw std::logic_error("Unknown MAC algorithm type");
	    }
    }
}
