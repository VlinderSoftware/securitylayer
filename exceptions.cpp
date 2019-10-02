#include "exceptions.hpp"
#include <stdexcept>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 {
void throwException(Errors error)
{
	switch (error)
	{
	case Errors::no_error__ :
		break;
	}
}
}




