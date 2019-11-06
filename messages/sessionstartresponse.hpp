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
    // sequence number is already part of the SPDU header
    // removed master ID from strawman proposal: it's not necessary
    
    /* Indicates the amount of time, in seconds, the session will be considered valid 
     * by the Outstation once the session is established (i.e. as of the moment 
     * SetSessionKeys is first sent). This value is informative to the Master. 
     * It is recommended that the Outstation use a (slightly) larger value for its own 
     * time-out so as to prevent a clock skew between the two devices from causing 
     * errors during the session.
     * The strawman proposal had this as a 24-bit value, but 32-bit aligns better */
    std::uint32_t session_key_change_interval_;
    /* Indicates the number of times the session keys may be used before they need 
     * to be replaced. */
    std::uint16_t session_key_change_count_;
    /* Contains the length of the challenge data, in bytes, that follows this header.
     * It should be reasonably small, but large enough to fit its cryptographic 
     * purpose. Minimal value is 4. */
    std::uint16_t challenge_data_length_;
}
#ifdef _MSC_VER
#pragma pack(pop)
#else
__attribute__((packed))
#endif
;
}}

#endif




