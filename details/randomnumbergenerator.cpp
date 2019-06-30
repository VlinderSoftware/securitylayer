#include "randomnumbergenerator.hpp"
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include <openssl/rand.h>
#include <limits>

using namespace std;

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 { namespace Details {
/*virtual */void RandomNumberGenerator::generate(boost::asio::mutable_buffer &buffer)/* override*/
{
	pre_condition(buffer.size() < decltype(buffer.size())(numeric_limits< int >::max()));
	int rc(RAND_bytes(static_cast< unsigned char* >(buffer.data()), buffer.size()));
	if (-1 == rc)
	{
		throw FailedToGenerateRandomData("OpenSSL reports random number generation is not supported here");
	}
	else if (0 == rc)
	{
		throw FailedToGenerateRandomData("Something went wrong generating random data");
	}
	else
	{ /* all is well */ }
}
}}



