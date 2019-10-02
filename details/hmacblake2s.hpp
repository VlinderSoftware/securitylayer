#ifndef dnp3sav6_details_hmacblake2s_hpp
#define dnp3sav6_details_hmacblake2s_hpp

#include "hmac.hpp"

namespace DNP3SAv6 { namespace Details { 
	class HMACBLAKE2s : public HMAC
	{
	public :
		HMACBLAKE2s();
		virtual ~HMACBLAKE2s() = default;

		HMACBLAKE2s(HMACBLAKE2s const&) = delete;
		HMACBLAKE2s(HMACBLAKE2s &&) = default;
		HMACBLAKE2s& operator=(HMACBLAKE2s const&) = delete;
		HMACBLAKE2s& operator=(HMACBLAKE2s &&) = default;
	};
}}

#endif
