#ifndef dnp3sav6_messages_sessionstartresponse_hpp
#define dnp3sav6_messages_sessionstartresponse_hpp

#include "../config.h"
#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct SessionStartResponse
{
    // sequence number is already part of the SPDU header
    // removed master ID from strawman proposal: it's not necessary
    
#if !defined(OPTION_MASTER_SETS_KWA_AND_MAL) || defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS)
    /* Indicates the key-wrap algorithm to be used. SAv6 mandates the use of at least
     * AES-256. The value is one of KeyWrapAlgorithm's values. */
    std::uint8_t key_wrap_algorithm_;
    /* The MAC algorithm to be used. SAv6 mandates the use of at least HMAC SHA-256. 
     *The value is one of MACAlgorithm's values. */
    std::uint8_t mac_algorithm_;
#endif
    /* Indicates the amount of time, in seconds, the session will be considered valid 
     * by the Master once the session is established (i.e. as of the moment 
     * SetSessionKeys is first sent). This value is informative to the Outstation. 
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
};
}}

#endif




