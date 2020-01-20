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
#ifndef dnp3sav6_details_hmacaeadadapter_hpp
#define dnp3sav6_details_hmacaeadadapter_hpp

#include "ihmac.hpp"
#include <openssl/crypto.h>

namespace DNP3SAv6 { namespace Details { 
    template < typename AEAD, AEADAlgorithm algorithm__ >
	class HMACAEADAdapter : public IHMAC
	{
	public :
        static AEADAlgorithm const algorithm = algorithm__;

        HMACAEADAdapter()
            : aead_(typename AEAD::use_as_digest())
        {
        }

		~HMACAEADAdapter()
        { /* no-op */ }

		HMACAEADAdapter(HMACAEADAdapter const&) = delete;
		HMACAEADAdapter(HMACAEADAdapter &&) = default;
		HMACAEADAdapter& operator=(HMACAEADAdapter const&) = delete;
		HMACAEADAdapter& operator=(HMACAEADAdapter &&) = default;

        virtual void setKey(boost::asio::const_buffer const &key) override
        {
            aead_.setKey(key);
        }
		virtual void digest(boost::asio::const_buffer const &data) override
        {
            aead_.addAssociatedData(data);
        }
		virtual boost::asio::const_buffer get() override
        {
            return aead_.getTag(boost::asio::mutable_buffer(tag_, sizeof(tag_)));
        }
		virtual bool verify(boost::asio::const_buffer const &digest) override
        {
            aead_.getTag(boost::asio::mutable_buffer(tag_, sizeof(tag_)));
            return (digest.size() <= sizeof(tag_)) && (CRYPTO_memcmp(digest.data(), tag_, digest.size()) == 0);
        }

    private :
        AEAD aead_;
        unsigned char tag_[16];
	};
}}

#endif
