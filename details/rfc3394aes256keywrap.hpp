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
#ifndef dnp3sav6_details_rfc3394aes256keywrap_hpp
#define dnp3sav6_details_rfc3394aes256keywrap_hpp

#include "ikeywrap.hpp" 

namespace DNP3SAv6 { namespace Details {
class RFC3394AES256KeyWrap : public IKeyWrap
{
public:
	RFC3394AES256KeyWrap();
	virtual ~RFC3394AES256KeyWrap();

	RFC3394AES256KeyWrap(RFC3394AES256KeyWrap const&) = delete;
	RFC3394AES256KeyWrap(RFC3394AES256KeyWrap &&) = delete;
	RFC3394AES256KeyWrap& operator=(RFC3394AES256KeyWrap const&) = delete;
	RFC3394AES256KeyWrap& operator=(RFC3394AES256KeyWrap &&) = delete;

    static constexpr size_t getWrappedDataSize(size_t input_data_size) { return input_data_size + 8; }
    static constexpr size_t getUnwrappedDataSize(size_t input_data_size) { return input_data_size - 8; }

	virtual void wrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const override;
	virtual bool unwrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const override;

private :
	static unsigned char const default_iv__[8];
};
}}

#endif
