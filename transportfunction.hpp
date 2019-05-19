#ifndef dnp3sav6_transportfunction_hpp
#define dnp3sav6_transportfunction_hpp

namespace DNP3SAv6 {
struct TransportFunction
{
	// Notify the transport function thatn anSDPU is ready for consumption.
	// This shall not throw. It may call the security layer back 
	void onSPDU() noexcept;
};
}

#endif



