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
#ifndef dnp3sav6_messages_sessionkeychangerequest_hpp
#define dnp3sav6_messages_sessionkeychangerequest_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct SessionKeyChangeRequest
{
    /* Indicates the key-wrap algorithm to be used. SAv6 mandates the use of at least
     * AES-256. The value is one of KeyWrapAlgorithm's values. */
    std::uint8_t key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
    /* The MAC algorithm to be used. SAv6 mandates the use of at least HMAC SHA-256. 
     *The value is one of MACAlgorithm's values. */
    std::uint8_t aead_algorithm_ = 4/* HMAC SHA256 T16*/;
    /* Contains the length of the encrypted key-wrap data, in bytes, that follows this
     * header. */
    std::uint16_t key_wrap_data_length_;
};
}}

#endif




