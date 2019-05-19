#ifndef dnp3sav6_messages_error_hpp
#define dnp3sav6_messages_error_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct Error
{
	enum ErrorCode : std::uint16_t {
		  invalid_spdu__ = 1
		};

	Error(ErrorCode error)
		: error_(error)
	{ /* no-op */ }

	std::uint16_t error_;
};
static_assert(sizeof(Error) == 2, "unexpected padding");
}}

#endif




