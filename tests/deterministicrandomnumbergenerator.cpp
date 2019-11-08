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
#include "deterministicrandomnumbergenerator.hpp"
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <limits>

using namespace std;
using namespace boost::asio;

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 { namespace Tests {
DeterministicRandomNumberGenerator::DeterministicRandomNumberGenerator()
{
	unsigned char seed[32] = {0};
	setSeed(const_buffer(seed, sizeof(seed)));
}

DeterministicRandomNumberGenerator::DeterministicRandomNumberGenerator(boost::asio::const_buffer const &seed)
{
	setSeed(seed);
}

void DeterministicRandomNumberGenerator::setSeed(boost::asio::const_buffer const &seed)
{
	SHA256_CTX ctx;
	int rc(SHA256_Init(&ctx));
	if (rc) rc = SHA256_Update(&ctx, seed.data(), seed.size());
	unsigned char key[32];
	if (rc) rc = SHA256_Final(key, &ctx);
	AES_set_encrypt_key(key, sizeof(key) * 8, &key_);
	memcpy(buffer_, key, sizeof(buffer_));
	AES_encrypt(buffer_, buffer_, &key_);
	avail_ = sizeof(buffer_);
}

/*virtual */void DeterministicRandomNumberGenerator::generate(boost::asio::mutable_buffer &buffer)/* override*/
{
	unsigned char *out(static_cast< unsigned char* >(buffer.data()));
	unsigned char *const end(out + buffer.size());
	static_assert(sizeof(decltype(avail_)) == sizeof(decltype(end - out)), "unexpected type for difference");
	invariant(avail_ < static_cast< decltype(avail_) >(numeric_limits< decltype(end - out) >::max()));
	while ((end - out) > static_cast< decltype(end - out) >(avail_))
	{
		memcpy(out, buffer_ + (sizeof(buffer_) - avail_), avail_);
		out += avail_;
		AES_encrypt(buffer_, buffer_, &key_);
		avail_ = sizeof(buffer_);
	}
	memcpy(out, buffer_ + (sizeof(buffer_) - avail_), end - out);
	avail_ -= (end - out);
}
}}



