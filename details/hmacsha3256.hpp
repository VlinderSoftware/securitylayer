#ifndef dnp3sav6_details_hmacsha3256_hpp
#define dnp3sav6_details_hmacsha3256_hpp

#include "hmac.hpp"

namespace DNP3SAv6 { namespace Details { 
	class HMACSHA3256 : public HMAC
	{
	public :
		HMACSHA3256();
		virtual ~HMACSHA3256() = default;

		HMACSHA3256(HMACSHA3256 const&) = delete;
		HMACSHA3256(HMACSHA3256 &&) = default;
		HMACSHA3256& operator=(HMACSHA3256 const&) = delete;
		HMACSHA3256& operator=(HMACSHA3256 &&) = default;
	};
}}

#endif
