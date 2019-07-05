#include "hmacsha3256.hpp"
#include <openssl/evp.h>

using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
	HMACSHA3256::HMACSHA3256()
		: HMAC(EVP_sha3_256())
	{ /* no-op */ }

}}

