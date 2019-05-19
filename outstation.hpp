#ifndef dnp3sav6_outstation_hpp
#define dnp3sav6_outstation_hpp

#include "securitylayer.hpp"

namespace DNP3SAv6 {
class Outstation : public SecurityLayer
{
public :
	Outstation(
		  boost::asio::io_context &io_context
		, Config config
		, TransportFunction *transport_function
		, ApplicationLayer *application_layer
		);
	~Outstation() = default;
	
	Outstation(Outstation &&other) noexcept = default;
	Outstation& operator=(Outstation &&other) noexcept = default;
	Outstation(Outstation const&) = delete;
	Outstation& operator=(Outstation const&) = delete;

protected :
	virtual void reset() noexcept override;
	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept override;

private :
	void sendRequestSessionInitiation() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
	Config config_;
};
}

#endif



