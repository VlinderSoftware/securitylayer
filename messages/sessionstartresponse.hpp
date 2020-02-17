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
#ifndef dnp3sav6_messages_sessionstartresponse_hpp
#define dnp3sav6_messages_sessionstartresponse_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
#ifdef _MSC_VER
#pragma pack(push)
#pragma pack(1)
#endif
struct SessionStartResponse
{
    /* Contains the length of the challenge data, in bytes, that follows this header.
     * It should be reasonably small, but large enough to fit its cryptographic 
     * purpose. Minimal value is 4. */
    std::uint8_t challenge_data_length_;
}
#ifdef _MSC_VER
#pragma pack(pop)
#else
__attribute__((packed))
#endif
;
}}

#endif




