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
#ifndef dnp3sav6_iencryption_hpp
#define dnp3sav6_iencryption_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { 
class IEncryption
{
public :
	IEncryption() = default;
	virtual ~IEncryption() = default;

	IEncryption(IEncryption const&) = delete;
	IEncryption(IEncryption &&) = delete;
	IEncryption& operator=(IEncryption const&) = delete;
	IEncryption& operator=(IEncryption &&) = delete;

    virtual void setIV(boost::asio::const_buffer const &iv) = 0;
    virtual boost::asio::const_buffer getIV() const = 0;

	virtual boost::asio::mutable_buffer encrypt(boost::asio::mutable_buffer const &out, boost::asio::const_buffer const &cleartext) = 0;
	virtual boost::asio::mutable_buffer decrypt(boost::asio::mutable_buffer const &out, boost::asio::const_buffer const &ciphertext) = 0;
};
}

#endif
