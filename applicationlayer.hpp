#ifndef dnp3sav6_applicationlayer_hpp
#define dnp3sav6_applicationlayer_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 {
struct ApplicationLayer
{
	// Notify the application layer that an APDU is ready for consumption.
	// This shall not throw. It may call the security layer back 
	void onAPDU() noexcept;
};
}

#endif



