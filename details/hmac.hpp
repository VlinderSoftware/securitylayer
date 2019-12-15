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
#ifndef dnp3sav6_details_hmac_hpp
#define dnp3sav6_details_hmac_hpp

#include "ihmac.hpp"
#include "../aeadalgorithm.hpp"

typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;

namespace DNP3SAv6 { namespace Details { 
	class HMAC : public IHMAC
	{
	public :
		virtual ~HMAC();

		HMAC(HMAC const&) = delete;
		HMAC(HMAC &&) = default;
		HMAC& operator=(HMAC const&) = delete;
		HMAC& operator=(HMAC &&) = default;

		virtual void setKey(boost::asio::const_buffer const &key) override;
		virtual void digest(boost::asio::const_buffer const &data) override;
		virtual boost::asio::const_buffer get() override;
		virtual bool verify(boost::asio::const_buffer const &digest) override;

	protected :
		HMAC(EVP_MD const *digest_algorithm);

	private :
		EVP_MD const *digest_algorithm_ = nullptr;
		EVP_MD_CTX *context_ = nullptr;
		bool finalized_ = false;
		unsigned char digest_[32]; /* if this changes for any algorithm, consider templatizing */
	};
}}

#endif
