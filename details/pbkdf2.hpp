/* Copyright 2020  Ronald Landheer-Cieslak
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
#ifndef dnp3sav6_details_pbkdf2_hpp
#define dnp3sav6_details_pbkdf2_hpp

#include <string>
#include <deque>
#include <vector>

namespace DNP3SAv6 { namespace Details {
class PBKDF2
{
public :
	PBKDF2(std::string const &password, std::vector< unsigned char > const &salt = std::vector< unsigned char >(), unsigned int iteration_count = 1000);
	~PBKDF2();
	PBKDF2(PBKDF2 const &) = delete;
	PBKDF2& operator=(PBKDF2 const &) = delete;
	PBKDF2(PBKDF2 &&) = default;
	PBKDF2& operator=(PBKDF2 &&) = default;

	std::vector< unsigned char > operator()(size_t n);

private :
    std::deque< unsigned char > key_;
};
}}

#endif

