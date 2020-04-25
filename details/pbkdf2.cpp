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
#include "pbkdf2.hpp"
#include <openssl/evp.h>
#include <stdexcept>
#include "../exceptions/contract.hpp"
using namespace std;

namespace DNP3SAv6 { namespace Details {
PBKDF2::PBKDF2(std::string const &password, std::vector< unsigned char > const &salt, unsigned int iteration_count/* = 1000*/)
{
	EVP_MD const *md(EVP_sha256());
	if (!md) throw bad_alloc();
    vector< unsigned char > key(32);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.empty() ? nullptr : &salt[0], salt.size(), iteration_count, md, key.size(), &key[0]))
    {
        throw runtime_error("failed to derive key");
    }
    else
    { /* no-op */ }
    key_.insert(key_.end(), key.begin(), key.end());
}
PBKDF2::~PBKDF2()
{
}

vector< unsigned char > PBKDF2::operator()(size_t n)
{
    pre_condition(n <= key_.size());
    auto end(key_.begin()); advance(end, n);
    vector< unsigned char > retval(key_.begin(), end);
    key_.erase(key_.begin(), end);
    return retval;
}
}}

