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
#ifndef dnp3sav6_details_aesgcm_hpp
#define dnp3sav6_details_aesgcm_hpp

#include "iaead.hpp"
#include <openssl/evp.h>
#include "intermediatebufferadapter.hpp"
#include "../aeadalgorithm.hpp"

namespace DNP3SAv6 { namespace Details { 
class AESGCM : public IAEAD
{
public :
    static AEADAlgorithm const algorithm = AEADAlgorithm::aes256_gcm__;

    AESGCM(
          boost::asio::mutable_buffer const &out
        , boost::asio::const_buffer const &key
        , boost::asio::const_buffer const &nonce
        , boost::asio::const_buffer const &associated_data
        , size_t authentication_tag_size
        );
    virtual ~AESGCM();

	AESGCM(AESGCM const&) = delete;
	AESGCM(AESGCM &&) = default;
	AESGCM& operator=(AESGCM const&) = delete;
	AESGCM& operator=(AESGCM &&) = default;

	virtual void encrypt(boost::asio::const_buffer const &plaintext) override;
    virtual boost::asio::const_buffer getEncrypted() override;
	virtual void decrypt(boost::asio::const_buffer const &ciphertext) override;
    virtual boost::asio::const_buffer getDecrypted() override;
    static constexpr size_t getKeySize() { return 32; }
    static constexpr size_t getIVSize() { return 12; }

private :
    enum State { undetermined__, encrypting__, decrypting__, error__ } state_ = undetermined__;
    EVP_CIPHER_CTX *context_ = nullptr;
    unsigned char iv_[12] = { 0 };
    boost::asio::const_buffer key_;
    boost::asio::const_buffer associated_data_;
    boost::asio::mutable_buffer out_;
    unsigned char *out_begin_ = nullptr;
    unsigned char *out_curr_ = nullptr;
    unsigned char *out_end_ = nullptr;
    size_t consumed_input_ = 0;
    unsigned char potential_tag_[16] = { 0 };
    IntermediateBufferAdapter tag_buffer_adapter_;
};
}}

#endif

