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
#include "nullencryption.hpp"
#include "../exceptions/contract.hpp"

using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
/*virtual */void NullEncryption::setIV(boost::asio::const_buffer const &iv)
{
    throw std::logic_error("This should not be called");
}
/*virtual */boost::asio::const_buffer NullEncryption::getIV() const
{
    throw std::logic_error("This should not be called");
}

/*virtual */mutable_buffer NullEncryption::encrypt(mutable_buffer const &out, boost::asio::const_buffer const &cleartext)
{
    pre_condition(out.size() >= cleartext.size());
    memcpy(out.data(), cleartext.data(), cleartext.size());
    return mutable_buffer(out.data(), cleartext.size());
}
/*virtual */mutable_buffer NullEncryption::decrypt(mutable_buffer const &out, boost::asio::const_buffer const &ciphertext)
{
    pre_condition(out.size() >= ciphertext.size());
    memcpy(out.data(), ciphertext.data(), ciphertext.size());
    return mutable_buffer(out.data(), ciphertext.size());
}
}}

