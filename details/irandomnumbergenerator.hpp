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
#ifndef dnp3sav6_details_irandomnumbergenerator_hpp
#define dnp3sav6_details_irandomnumbergenerator_hpp

#include <boost/asio.hpp>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 { namespace Details {
class IRandomNumberGenerator
{
public :
	IRandomNumberGenerator() = default;
	virtual ~IRandomNumberGenerator() = default;

	IRandomNumberGenerator(IRandomNumberGenerator const&) = delete;
	IRandomNumberGenerator& operator=(IRandomNumberGenerator const&) = delete;
	IRandomNumberGenerator(IRandomNumberGenerator&&) = default;
	IRandomNumberGenerator& operator=(IRandomNumberGenerator&&) = default;

	virtual void generate(boost::asio::mutable_buffer &buffer) = 0;
};
}}

#endif



