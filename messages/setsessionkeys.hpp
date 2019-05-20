#ifndef dnp3sav6_messages_setsessionkeys_hpp
#define dnp3sav6_messages_setsessionkeys_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct SetSessionKeys
{
    // sequence number is already part of the SPDU header

    /* Contains the length of the encrypted key-wrap data, in bytes, that follows this
     * header. */
    std::uint16_t key_wrap_data_length_;
};
}}

#endif




