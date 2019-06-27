#include "randomnumbergenerator.hpp"
#include <sodium.h>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 { namespace Details {
/*virtual */void RandomNumberGenerator::generate(boost::asio::mutable_buffer &buffer)/* override*/
{
	randombytes_buf(buffer.data(), buffer.size());
}
}}



