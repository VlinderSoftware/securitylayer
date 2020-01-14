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
#ifndef dnp3sav6_details_iaead_hpp
#define dnp3sav6_details_iaead_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details { 
	class IAEAD
	{
	public :
		IAEAD() = default;
		virtual ~IAEAD() = default;

		IAEAD(IAEAD const&) = delete;
		IAEAD(IAEAD &&) = default;
		IAEAD& operator=(IAEAD const&) = delete;
		IAEAD& operator=(IAEAD &&) = default;

		virtual void encrypt(boost::asio::const_buffer const &plaintext) = 0;
        virtual boost::asio::const_buffer getEncrypted() = 0;
		virtual void decrypt(boost::asio::const_buffer const &plaintext) = 0;
        virtual boost::asio::const_buffer getDecrypted() = 0;
	};
    template < typename AEADType >
    AEADType makeAEAD(boost::asio::mutable_buffer const &out, boost::asio::const_buffer const &key, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &associated_data)
    {
        return AEADType(out, key, nonce, associated_data, getAEADAlgorithmAuthenticationTagSize(AEADType::algorithm));
    }
    template < typename AEADType >
    constexpr unsigned int getKeySize()
    {
        return AEADType::getKeySize();
    }
}}

#endif
