#include "exceptions.hpp"
#include <stdexcept>

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




