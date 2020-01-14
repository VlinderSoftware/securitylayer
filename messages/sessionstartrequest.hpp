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
    // sequence number is already part of the SPDU header
    // removed master ID from strawman proposal: it's not necessary
    
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
    /* Indicates the key-wrap algorithm to be used. SAv6 mandates the use of at least
     * AES-256. The value is one of KeyWrapAlgorithm's values. */
    std::uint8_t key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
    /* The MAC algorithm to be used. SAv6 mandates the use of at least HMAC SHA-256. 
     *The value is one of MACAlgorithm's values. */
    std::uint8_t aead_algorithm_ = 4/* HMAC SHA256 T16*/;
    /* Indicates the amount of time, in seconds, the session will be considered valid 
     * by the Master once the session is established (i.e. as of the moment 
     * SetSessionKeys is first sent). This value is informative to the Outstation. 
     * It is recommended that the Outstation use a (slightly) larger value for its own 
     * time-out so as to prevent a clock skew between the two devices from causing 
     * errors during the session.
     * The strawman proposal had this as a 24-bit value, but 32-bit aligns better */
    std::uint32_t session_key_change_interval_ = 300/*five minutes*/;
    /* Indicates the number of times the session keys may be used before they need 
     * to be replaced. */
    std::uint16_t session_key_change_count_ = 4096;
}
#ifdef _MSC_VER
#pragma pack(pop)
#else
__attribute__((packed))
#endif
;
static_assert(sizeof(SessionStartRequest) == 10, "unexpected padding for SessionStartRequest");
}}

#endif




