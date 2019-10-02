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




