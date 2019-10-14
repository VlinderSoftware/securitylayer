#ifndef dnp3sav6_messages_authenticatedapdu_hpp
#define dnp3sav6_messages_authenticatedapdu_hpp

#include "../config.hpp"
#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct AuthenticatedAPDU
{
    AuthenticatedAPDU(std::uint16_t apdu_length = 0)
        : apdu_length_(apdu_length)
    { /* no-op */ }

    // sequence number is already part of the SPDU header

    std::uint16_t apdu_length_;
};
}}

#endif




