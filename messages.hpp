#ifndef dnp3sav6_messages_hpp
#define dnp3sav6_messages_hpp

#include <cstdint>
#include "messages/error.hpp"
#include "messages/requestsessioninitiation.hpp"
#include "messages/sessionstartrequest.hpp"

namespace DNP3SAv6 {
	enum struct Message : std::uint8_t
	{
	  request_session_initiation__	= 0x01
	, session_start_request__	= 0x02
	, session_start_response__	= 0x03
	, set_keys__			= 0x04
	, key_status__			= 0x05
	, authenticated_apdu__		= 0x06
	, error__			= 0x10 // must be 0x10 to be able to mimic IIN2.5
	};
}

#endif



