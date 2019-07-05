#include "hmacsha256.hpp"
#include <openssl/evp.h>

using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
	HMACSHA256::HMACSHA256()
		: HMAC(EVP_sha256())
	{ /* no-op */ }

}}

