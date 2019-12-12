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
#ifndef dnp3sav6_details_aes256encryption_hpp
#define dnp3sav6_details_aes256encryption_hpp

#include <boost/asio.hpp>
#include "../iencryption.hpp"

namespace DNP3SAv6 { namespace Details { 
class AES256CBCEncryption : public IEncryption
{
public :
	AES256CBCEncryption(boost::asio::const_buffer const &key, boost::asio::const_buffer const &initial_iv);
	virtual ~AES256CBCEncryption() = default;

	AES256CBCEncryption(AES256CBCEncryption const&) = delete;
	AES256CBCEncryption(AES256CBCEncryption &&) = delete;
	AES256CBCEncryption& operator=(AES256CBCEncryption const&) = delete;
	AES256CBCEncryption& operator=(AES256CBCEncryption &&) = delete;

    virtual void setIV(boost::asio::const_buffer const &iv);
    virtual boost::asio::const_buffer getIV() const;

	virtual boost::asio::mutable_buffer encrypt(boost::asio::mutable_buffer const &out, boost::asio::const_buffer const &cleartext) override;
	virtual boost::asio::mutable_buffer decrypt(boost::asio::mutable_buffer const &out, boost::asio::const_buffer const &ciphertext) override;

private :
    union WorkBuffer
    {
        struct FirstChunk
        {
            std::uint16_t size_;
            unsigned char data_[14];
        } first_chunk_;
        struct SubsequentChunks
        {
            unsigned char data_[16];
        } subsequent_chunks_;
        unsigned char data_[16];
    };

    void encryptWorkBuffer();
    void decryptWorkBuffer();
    bool checkPadding(boost::asio::const_buffer const &padding_data, unsigned char expected_padding) const;

    boost::asio::const_buffer key_;
    unsigned char initialization_vector_[16];
    WorkBuffer work_buffer_;
    static_assert(sizeof(work_buffer_) == 16, "Unexpected padding in work buffer");
    static_assert(offsetof(WorkBuffer, first_chunk_.data_) == 2, "Unexpected padding in work buffer");
};
}}

#endif
