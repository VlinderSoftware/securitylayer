#ifndef dnp3sav6_messages_hpp
#define dnp3sav6_messages_hpp

#include <cstdint>
#include "messages/requestsessioninitiation.hpp"
#include "messages/sessionstartrequest.hpp"

namespace DNP3SAv6 {
	enum struct Message : std::uint16_t
	{
		  session_start_request__	= 0x0101
		, request_session_initiation__	= 0x0201
	};
}

#endif



