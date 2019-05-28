#include "randomnumbergenerator.hpp"
#include <sodium.h>

namespace DNP3SAv6 { namespace Details {
/*virtual */void RandomNumberGenerator::generate(boost::asio::mutable_buffer &buffer)/* override*/
{
	randombytes_buf(buffer.data(), buffer.size());
}
}}



