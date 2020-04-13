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
#include "hkdf.hpp"
#include <memory>

using namespace std;

namespace DNP3SAv6 { namespace Details {
HKDF::HKDF(vector< unsigned char > const &salt, vector< unsigned char > const &ikm)
	: counter_(0)
	, offset_(0)
{
	OpenSSL_add_all_digests();
	generatePRK(salt, ikm);
}

vector< unsigned char > HKDF::operator()(size_t n)
{
	vector< unsigned char > retval;
	while (retval.size() < n)
	{
		unsigned int remaining(okm_.size() - offset_);
		if (remaining == 0)
		{
			generateOKM();
		}
		else
		{
			if (remaining > n) remaining = n;
			retval.insert(retval.end(), okm_.begin() + offset_, okm_.begin() + (offset_ + remaining));
			offset_ += remaining;
			n -= remaining;
		}
	}

	return retval;
}

void HKDF::generatePRK(vector< unsigned char > const &salt, vector< unsigned char > const &ikm)
{
	auto mdctx_deleter([](EVP_MD_CTX *mdctx){ EVP_MD_CTX_destroy(mdctx); });
	unique_ptr< EVP_MD_CTX, decltype(mdctx_deleter) > mdctx(EVP_MD_CTX_create(), mdctx_deleter);
	if (!mdctx.get()) throw bad_alloc();

	EVP_MD const *md(EVP_sha256());
	if (!md) throw bad_alloc();

	int rc(EVP_DigestInit_ex(mdctx.get(), md, NULL));
	if (1 != rc) throw bad_alloc();
	rc = EVP_DigestUpdate(mdctx.get(), &salt[0], salt.size());
	if (1 != rc) throw bad_alloc();
	rc = EVP_DigestUpdate(mdctx.get(), &ikm[0], ikm.size());
	if (1 != rc) throw bad_alloc();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	if (1 == rc) rc = EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len);
	if (1 != rc) throw bad_alloc();

	prk_.clear();
	prk_.insert(prk_.end(), md_value, md_value + md_len);
}

void HKDF::generateOKM()
{
	auto mdctx_deleter([](EVP_MD_CTX *mdctx){ EVP_MD_CTX_destroy(mdctx); });
	unique_ptr< EVP_MD_CTX, decltype(mdctx_deleter) > mdctx(EVP_MD_CTX_create(), mdctx_deleter);
	if (!mdctx.get()) throw bad_alloc();
	EVP_MD const *md(EVP_sha256());
	if (!md) throw bad_alloc();

	int rc(EVP_DigestInit_ex(mdctx.get(), md, NULL));
	if (1 != rc) throw bad_alloc();
	rc = EVP_DigestUpdate(mdctx.get(), &prk_[0], prk_.size());
	if (1 != rc) throw bad_alloc();
	rc = EVP_DigestUpdate(mdctx.get(), &okm_[0], okm_.size());
	if (1 != rc) throw bad_alloc();
	rc = EVP_DigestUpdate(mdctx.get(), &counter_, 1);
	if (1 != rc) throw bad_alloc();
	++counter_;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	if (1 == rc) rc = EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len);
	if (1 != rc) throw bad_alloc();

	okm_.clear();
	okm_.insert(okm_.end(), md_value, md_value + md_len);
}

}}



