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
#ifndef dnp3sav6_details_aeadhmacadapter_hpp
#define dnp3sav6_details_aeadhmacadapter_hpp

#include "iaead.hpp"
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include "../aeadalgorithm.hpp"
#include "intermediatebufferadapter.hpp"
#include <algorithm>
#include <openssl/crypto.h>

namespace DNP3SAv6 { namespace Details { 
    template < typename HMAC, AEADAlgorithm algorithm__ >
	class AEADHMACAdapter : public IAEAD
	{
	public :
        static AEADAlgorithm const algorithm = algorithm__;

        AEADHMACAdapter(
              boost::asio::mutable_buffer const &out
            , boost::asio::const_buffer const &key
            , boost::asio::const_buffer const &nonce
            , boost::asio::const_buffer const &associated_data
            , size_t tag_size
            )
            : out_(out)
            , begin_(static_cast< unsigned char* >(out_.data()))
            , curr_(begin_)
            , end_(curr_ + out_.size())
            , tag_buffer_adapter_(boost::asio::mutable_buffer(potential_tag_, tag_size))
            , tag_size_(tag_size)
        {
            pre_condition(tag_size <= getMaxTagSize());
            hmac_.setKey(key);
            hmac_.digest(associated_data);
            hmac_.digest(nonce);
        }

		~AEADHMACAdapter()
        { /* no-op */ }

		AEADHMACAdapter(AEADHMACAdapter const&) = delete;
		AEADHMACAdapter(AEADHMACAdapter &&) = default;
		AEADHMACAdapter& operator=(AEADHMACAdapter const&) = delete;
		AEADHMACAdapter& operator=(AEADHMACAdapter &&) = default;

		/*virtual */void encrypt(boost::asio::const_buffer const &plaintext)/* = 0*/
        {
            if (state_ == undetermined__) state_ = encrypting__;
            error_ |= (state_ != encrypting__);
            hmac_.digest(plaintext);
            auto size_to_copy(std::min< size_t >(std::distance(curr_, end_), plaintext.size()));
            error_ |= (size_to_copy < plaintext.size());
            unsigned char const *plaintext_begin(static_cast< unsigned char const * >(plaintext.data()));
            unsigned char const *const plaintext_end(plaintext_begin + plaintext.size());
            curr_ = std::copy(plaintext_begin, plaintext_end, curr_);
        }

        /*virtual */boost::asio::const_buffer getEncrypted()/* = 0*/
        {
            error_ |= (state_ != encrypting__);
            if (error_) return boost::asio::const_buffer();

            auto hmac_result(hmac_.get());
            auto const size_to_copy(std::min< size_t >(std::distance(curr_, end_), hmac_result.size()));
            unsigned char const *hmac_result_begin(static_cast< unsigned char const* >(hmac_result.data()));
            unsigned char const *const hmac_result_end(hmac_result_begin + size_to_copy);
            curr_ = std::copy(hmac_result_begin, hmac_result_end, curr_);

            unsigned char *const out_begin(static_cast< unsigned char * >(out_.data()));
            size_t out_size(std::distance(out_begin, curr_));
            out_ = boost::asio::mutable_buffer(out_.data(), out_size);
            return out_;
        }

		/*virtual */void decrypt(boost::asio::const_buffer const &plaintext)/* = 0*/
        {
            if (state_ == undetermined__) state_ = decrypting__;
            error_ |= (state_ != decrypting__);

            // We keep the latest N bytes, where N is the size of the tag, in a buffer and run the rest though the 
            // digest in FIFO order. That way, we can check the tag (which will be in the buffer) against the digest. 
            // Note that because this is an HMAC AEAD, but we don't have the original plaintext length, we can't 
            // validate the original plaintext length here, so the client code will have to do that.
            unsigned char buffer[32];
            unsigned char const *plaintext_curr(static_cast< unsigned char const * >(plaintext.data()));
            unsigned char const *const plaintext_end(plaintext_curr + plaintext.size());
            while (plaintext_curr != plaintext_end)
            {
                size_t const remaining(std::distance(plaintext_curr, plaintext_end));
                auto push_result(tag_buffer_adapter_.push(boost::asio::mutable_buffer(buffer, sizeof(buffer)), boost::asio::const_buffer(plaintext_curr, remaining)));
                size_t const throughput_produced(push_result.first);
                size_t const input_consumed(push_result.second);
                assert((plaintext_curr + input_consumed) <= plaintext_end);
                plaintext_curr += input_consumed;
                hmac_.digest(boost::asio::const_buffer(buffer, throughput_produced));
                auto size_to_copy(std::min< size_t >(std::distance(curr_, end_), throughput_produced));
                error_ |= (size_to_copy < throughput_produced);
                unsigned char const *throughput_begin(buffer);
                unsigned char const *const throughput_end(throughput_begin + throughput_produced);
                curr_ = std::copy(throughput_begin, throughput_end, curr_);
            }
        }

        /*virtual */boost::asio::const_buffer getDecrypted()/* = 0*/
        {
            error_ |= (state_ != decrypting__);
            if (error_) return boost::asio::const_buffer();

            auto hmac_result(hmac_.get());
            if (hmac_result.size() < tag_size_) return boost::asio::const_buffer();
            if (CRYPTO_memcmp(hmac_result.data(), potential_tag_, tag_size_) != 0) return boost::asio::const_buffer();

            return boost::asio::const_buffer(begin_, std::distance(begin_, curr_));
        }

        /* all of the algorithms we use at the moment have a 32-byte key size, so I guess we're lucky :) */
        static constexpr unsigned int getKeySize() { return 32; }
        /* all of the algorithms we use have a 32-byte block size, but we truncate at smaller than that. I could have put 16 as the value here, but I do want to be future-proof */
        static constexpr unsigned int getMaxTagSize() { return 32; }

    private :
        enum State { undetermined__, encrypting__, decrypting__ } state_ = undetermined__;
        boost::asio::mutable_buffer out_;
        boost::asio::const_buffer nonce_;
        boost::asio::const_buffer associated_data_;
        unsigned char *const begin_ = nullptr;
        unsigned char *curr_ = nullptr;
        unsigned char *const end_ = nullptr;
        bool error_ = false;
        HMAC hmac_;
        unsigned char potential_tag_[getMaxTagSize()];
        size_t tag_size_;
        IntermediateBufferAdapter tag_buffer_adapter_;
	};
}}

#endif
