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
#ifndef dnp3sav6_messages_sessionstartrequest_hpp
#define dnp3sav6_messages_sessionstartrequest_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
#ifdef _MSC_VER
#pragma pack(push)
#pragma pack(1)
#endif
struct SessionStartRequest
{
    /* The version field is an 8-bit (changed from 16 vs. my strawman proposal to allow
     * for better alignment) numerical identifier for the current version. For SAv6,
     * the value is always 6. Future versions of the protocol should keep this value
     * in the same place (and should use the same function code for this message, 
     * even if the content changes). */
    std::uint8_t version_ = 6;
    /* The flags field allows the Master to indicate that it supports other versions
     * of the protocol. It's an 8-bit field of which bits 7 through 1 are reserved
     * and shall be 0. Bit 0 is set to 1 if the Master supports higher versions
     * than what is currently requested, or 0 if not. */
    std::uint8_t flags_ = 0;
}
#ifdef _MSC_VER
#pragma pack(pop)
#else
__attribute__((packed))
#endif
;
static_assert(sizeof(SessionStartRequest) == 2, "unexpected padding for SessionStartRequest");
}}

#endif




