#ifndef dnp3sav6_messages_error_hpp
#define dnp3sav6_messages_error_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Messages {
struct Error
{
	enum ErrorCode : std::uint16_t {
		  invalid_spdu__ = 1
		, unsupported_version__
		, unexpected_flags__
		, unsupported_mac_algorithm__
		, unsupported_keywrap_algorithm__
        , unexpected_spdu__
        , authentication_failure__
		};

	Error(ErrorCode error)
		: error_(error)
	{ /* no-op */ }

	std::uint16_t error_;
};
static_assert(sizeof(Error) == 2, "unexpected padding");
}}

#endif




