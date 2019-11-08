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
#ifndef dnp3sav6_messages_sessionconfirmation_hpp
#define dnp3sav6_messages_sessionconfirmation_hpp

#include "../config.hpp"
#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct SessionConfirmation
{
    SessionConfirmation(std::uint16_t mac_length = 0)
        : mac_length_(mac_length)
    { /* no-op */ }

    // sequence number is already part of the SPDU header

    std::uint16_t mac_length_;
};
}}

#endif




