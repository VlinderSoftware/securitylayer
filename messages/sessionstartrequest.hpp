#ifndef dnp3sav6_messages_sessionstartrequest_hpp
#define dnp3sav6_messages_sessionstartrequest_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct SessionStartRequest
{
	std::uint32_t seq_;
	std::uint16_t type_;
};
}}

#endif




