#ifndef dnp3sav6_details_hmacsha256_hpp
#define dnp3sav6_details_hmacsha256_hpp

#include "hmac.hpp"

namespace DNP3SAv6 { namespace Details { 
	class HMACSHA256 : public HMAC
	{
	public :
		HMACSHA256();
		virtual ~HMACSHA256() = default;

		HMACSHA256(HMACSHA256 const&) = delete;
		HMACSHA256(HMACSHA256 &&) = default;
		HMACSHA256& operator=(HMACSHA256 const&) = delete;
		HMACSHA256& operator=(HMACSHA256 &&) = default;
	};
}}

#endif
