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
#ifndef dnp3sav6_details_hkdf_hpp
#define dnp3sav6_details_hkdf_hpp

#include <openssl/evp.h>
#include <vector>

namespace DNP3SAv6 { namespace Details {
class HKDF
{
public :
	HKDF(std::vector< unsigned char > const &salt, std::vector< unsigned char > const &ikm);
	~HKDF() = default;
	HKDF(HKDF const &) = delete;
	HKDF& operator=(HKDF const &) = delete;
	HKDF(HKDF &&) = default;
	HKDF& operator=(HKDF &&) = default;

	std::vector< unsigned char > operator()(size_t n);

private :
	void generatePRK(std::vector< unsigned char > const &salt, std::vector< unsigned char > const &ikm);
	void generateOKM();

	std::vector< unsigned char > prk_;
	std::vector< unsigned char > okm_;
	unsigned char counter_;
	unsigned int offset_;
};
}}

#endif

