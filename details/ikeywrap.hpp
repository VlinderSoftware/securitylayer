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
#ifndef dnp3sav6_details_ikeywrap_hpp
#define dnp3sav6_details_ikeywrap_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details { 
class IKeyWrap
{
public :
	IKeyWrap() = default;
	virtual ~IKeyWrap() = default;

	IKeyWrap(IKeyWrap const&) = delete;
	IKeyWrap(IKeyWrap &&) = delete;
	IKeyWrap& operator=(IKeyWrap const&) = delete;
	IKeyWrap& operator=(IKeyWrap &&) = delete;

	virtual void wrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const = 0;
	virtual bool unwrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const = 0;
};
}}

#endif
