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



