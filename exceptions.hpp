#ifndef dnp3sav6_exceptions_hpp
#define dnp3sav6_exceptions_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "exceptions/exception.hpp"
namespace DNP3SAv6 {
	enum struct Errors {
		  no_error__
	};
	
//	typedef Exceptions::Exception< std::logic_error, Errors, Errors::busy__ > Busy;

	void throwException(Errors error);
}

#endif
