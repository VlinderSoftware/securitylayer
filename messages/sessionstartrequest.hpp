#ifndef dnp3sav6_messages_sessionstartrequest_hpp
#define dnp3sav6_messages_sessionstartrequest_hpp

#include "../config.h"
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
    
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
    /* Indicates the key-wrap algorithm to be used. SAv6 mandates the use of at least
     * AES-256. The value is one of KeyWrapAlgorithm's values. */
    std::uint8_t key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
    /* The MAC algorithm to be used. SAv6 mandates the use of at least HMAC SHA-256. 
     *The value is one of MACAlgorithm's values. */
    std::uint8_t mac_algorithm_ = 4/* HMAC SHA256 T16*/;
#endif
    /* Indicates the amount of time, in seconds, the session will be considered valid 
     * by the Master once the session is established (i.e. as of the moment 
     * SetSessionKeys is first sent). This value is informative to the Outstation. 
     * It is recommended that the Outstation use a (slightly) larger value for its own 
     * time-out so as to prevent a clock skew between the two devices from causing 
     * errors during the session.
     * The strawman proposal had this as a 24-bit value, but 32-bit aligns better */
    std::uint32_t session_key_change_interval_ = 60/*one hour*/;
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
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
static_assert(sizeof(SessionStartRequest) == 10, "unexpected padding for SessionStartRequest");
#else
static_assert(sizeof(SessionStartRequest) == 8, "unexpected padding for SessionStartRequest");
#endif
}}

#endif




