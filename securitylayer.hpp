#ifndef dnp3sav6_securitylayer_hpp
#define dnp3sav6_securitylayer_hpp

#include <boost/asio.hpp>
#include "config.hpp"
#include "exceptions.hpp"
#include "statistics.hpp"

namespace DNP3SAv6 {
class SecurityLayer
{
public :
	SecurityLayer(
		  boost::asio::io_context &io_context
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
	enum UpdateResult {
		  wait__
		};

	// signal link loss (from lower layers)
	void onLinkLost() noexcept;
	// signal application reset (from application layer)
	void onApplicationReset() noexcept;
	// signal an application layer timeout
	void onAPDUTimeout() noexcept;

	void postAPDU(boost::asio::const_buffer const &apdu) noexcept;
	void postSPDU(boost::asio::const_buffer const &spdu) noexcept;

	bool pollAPDU() const noexcept;
	bool pollSPDU() const noexcept;

	boost::asio::const_buffer getAPDU() noexcept;
	boost::asio::const_buffer getSPDU() noexcept;

	std::pair< UpdateResult, boost::asio::steady_timer::duration > update() noexcept;

protected :
	enum State {
		  initial__
		, expect_session_start_request__
		, expect_session_start_response__
		, expect_set_keys__
		, expect_key_status__
		, active__
		};

	virtual void reset() noexcept = 0;

	void setOutgoingSPDU(
		  boost::asio::const_buffer const &spdu
		, boost::asio::steady_timer::duration const &timeout = std::chrono::milliseconds(0)
		) noexcept;
	State getState() const noexcept { return state_; }
	void setState(State state) noexcept { state_ = state; }
	void incrementStatistic(Statistics statistics) noexcept { /*TODO*/ }

	void discardAPDU() noexcept;
	void queueAPDU(boost::asio::const_buffer const &apdu) noexcept;

	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept = 0;

	void incrementSEQ() noexcept { seq_++; }
	std::uint32_t getSEQ() const noexcept { return seq_; }

	void sendAuthenticatedAPDU(boost::asio::const_buffer const &apdu) noexcept;

private :
	void parseIncomingSPDU() noexcept;

	State state_ = initial__;
	boost::asio::const_buffer outgoing_apdu_;
	boost::asio::const_buffer outgoing_spdu_;
	boost::asio::const_buffer incoming_apdu_;
	boost::asio::const_buffer incoming_spdu_;

	unsigned char incoming_spdu_buffer_[Config::max_spdu_size__];
	unsigned char outgoing_apdu_buffer_[Config::max_apdu_size__];

	boost::asio::steady_timer timeout_;

	std::uint32_t seq_;
};
}

#endif


