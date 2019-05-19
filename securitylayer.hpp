#ifndef dnp3sav6_securitylayer_hpp
#define dnp3sav6_securitylayer_hpp

#include <boost/asio.hpp>
#include "applicationlayer.hpp"
#include "exceptions.hpp"
#include "transportfunction.hpp"

namespace DNP3SAv6 {
class SecurityLayer
{
public :
	SecurityLayer(
		  TransportFunction *transport_function
		, ApplicationLayer *application_layer
		);
	~SecurityLayer() = default;
	
	SecurityLayer(SecurityLayer &&other) noexcept = default;
	SecurityLayer& operator=(SecurityLayer &&other) noexcept = default;
	SecurityLayer(SecurityLayer const&) = delete;
	SecurityLayer& operator=(SecurityLayer const&) = delete;

public :
// public interface: we receive APDUs to send along as SPDUs and we receive
// SPDUs to send along as APDUs. Some SPDUs never make it through because
// they're internal to the security protocol - but that's OK.
// We also need to know when the link is lost, or when the application is reset.
	// signal link loss (from lower layers)
	void onLinkLost() noexcept;
	// signal application reset (from application layer)
	void onApplicationReset() noexcept;

	void postAPDU(boost::asio::const_buffer const &apdu);
	void postSPDU(boost::asio::const_buffer const &spdu);
	Errors postAPDU(boost::asio::const_buffer const &apdu, std::nothrow_t const&) noexcept;
	Errors postSPDU(boost::asio::const_buffer const &spdu, std::nothrow_t const&) noexcept;

	bool pollAPDU() const noexcept;
	bool pollSPDU() const noexcept;

	boost::asio::const_buffer getAPDU() const;
	boost::asio::const_buffer getSPDU() const;
	std::pair< boost::asio::const_buffer, Errors > getAPDU(std::nothrow_t const&) const;
	std::pair< boost::asio::const_buffer, Errors > getSPDU(std::nothrow_t const&) const;

private :
	enum State {
		  initial__
		};

	void reset() noexcept;

	TransportFunction *transport_function_ = nullptr;
	ApplicationLayer *application_layer_ = nullptr;
	State state_ = initial__;
};
}

#endif


