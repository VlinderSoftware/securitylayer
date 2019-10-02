#include "hmacblake2s.hpp"
#include <openssl/evp.h>

using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
	HMACBLAKE2s::HMACBLAKE2s()
		: HMAC(EVP_blake2s256())
	{ /* no-op */ }

}}

