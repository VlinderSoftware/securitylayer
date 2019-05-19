#ifndef dnp3sav6_messages_requestsessioninitiation_hpp
#define dnp3sav6_messages_requestsessioninitiation_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct RequestSessionInitiation
{
	std::uint32_t seq_;
	std::uint16_t type_;
};
}}

#endif



