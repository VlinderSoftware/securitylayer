#ifndef dnp3sav6_messages_keystatus_hpp
#define dnp3sav6_messages_keystatus_hpp

#include "../config.h"
#ifndef OPTION_REMOVE_KEY_STATUS_MESSAGE
#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct KeyStatus
{
    // sequence number is already part of the SPDU header

    /* key status */
    std::uint8_t key_status_;
};
}}
#endif

#endif




