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
#include "ecdh.hpp"
#include "privatekey.hpp"
#include "publickey.hpp"
#include <memory>

using namespace std;

namespace DNP3SAv6 { namespace Details {
vector< unsigned char > ecdh(PrivateKey const &private_key, PublicKey const &peer_key)
{
	auto ctx_deleter([](EVP_PKEY_CTX *ctx){ EVP_PKEY_CTX_free(ctx); });
	unique_ptr< EVP_PKEY_CTX, decltype(ctx_deleter) > ctx(EVP_PKEY_CTX_new(private_key.key_, NULL), ctx_deleter);
	if (!ctx.get()) throw bad_alloc();
	int rc(EVP_PKEY_derive_init(ctx.get()));
	if (1 == rc) rc = EVP_PKEY_derive_set_peer(ctx.get(), peer_key.key_);
	size_t secret_len(0);
	if (1 == rc) rc = EVP_PKEY_derive(ctx.get(), nullptr, &secret_len);
	vector< unsigned char > retval;
	if (1 == rc) retval.resize(secret_len);
	if (1 == rc) rc = EVP_PKEY_derive(ctx.get(), &retval[0], &secret_len);
	
	return retval;
}
}}



