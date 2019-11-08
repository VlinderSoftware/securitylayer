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
#include "hmac.hpp"
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "hmacblake2s.hpp"
#include "hmacsha256.hpp"
#include "hmacsha3256.hpp"
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
	HMAC::HMAC(EVP_MD const *digest_algorithm)
		: digest_algorithm_(digest_algorithm)
	{
		invariant(digest_algorithm_);
		invariant(EVP_MD_size(digest_algorithm_) == sizeof(digest_));
	}

	/*virtual */HMAC::~HMAC()
	{
		EVP_MD_CTX_free(context_);
	}

	/*virtual */void HMAC::setKey(const_buffer const &key)/* override*/
	{
		pre_condition(!finalized_);
		pre_condition(!context_);
		context_ = EVP_MD_CTX_new();
		post_condition(context_);
		if (1 != EVP_DigestInit_ex(context_, digest_algorithm_, NULL/*no engine*/))
		{
			throw DigestFailed("Failed to initialize digest algorithm");
		}
		else
		{ /* all is well */ }
		if (1 != EVP_DigestUpdate(context_, key.data(), key.size()))
		{
			throw DigestFailed("Failed to hash the HMAC key");
		}
		else
		{ /* all is well */ }
	}
	/*virtual */void HMAC::digest(const_buffer const &data)/* override*/
	{
		pre_condition(!finalized_);
		pre_condition(context_);
		if (1 != EVP_DigestUpdate(context_, data.data(), data.size()))
		{
			throw DigestFailed("Failed to hash data");
		}
		else
		{ /* all is well */ }
	}
	/*virtual */const_buffer HMAC::get()/* override*/
	{
		if (!finalized_)
		{
			unsigned int digest_size;
			if (1 != EVP_DigestFinal_ex(context_, digest_, &digest_size))
			{
				throw DigestFailed("Failed to finalize hash");
			}
			else
			{ /* all is well */ }
			post_condition(digest_size == 32);
			finalized_ = true;
		}
		else
		{ /* already finalized */ }
		return const_buffer(digest_, sizeof(digest_));
	}
	/*virtual */bool HMAC::verify(const_buffer const &digest)/* override*/
	{
		auto our_digest(get());
		return (digest.size() <= our_digest.size()) && (CRYPTO_memcmp(digest.data(), our_digest.data(), digest.size()) == 0);
	}
}}

