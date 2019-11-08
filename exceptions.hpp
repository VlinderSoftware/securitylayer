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
#ifndef dnp3sav6_exceptions_hpp
#define dnp3sav6_exceptions_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "exceptions/exception.hpp"
namespace DNP3SAv6 {
	enum struct Errors {
		  no_error__
		, failed_to_generate_random_data__
		, digest_failed__
		, rfc3394_aes256_key_wrap_failure__
	};
	
	typedef Vlinder::Exceptions::Exception< std::runtime_error, Errors, Errors::failed_to_generate_random_data__ > FailedToGenerateRandomData;
	typedef Vlinder::Exceptions::Exception< std::runtime_error, Errors, Errors::digest_failed__ > DigestFailed;
	typedef Vlinder::Exceptions::Exception< std::runtime_error, Errors, Errors::rfc3394_aes256_key_wrap_failure__ > RFC3394AES256KeyWrapFailure;
	void throwException(Errors error);
}

#endif
