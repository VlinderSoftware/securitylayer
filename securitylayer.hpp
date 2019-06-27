#ifndef dnp3sav6_securitylayer_hpp
#define dnp3sav6_securitylayer_hpp

#include <boost/asio.hpp>
#include "config.hpp"
#include "exceptions.hpp"
#include "statistics.hpp"
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"

namespace DNP3SAv6 {
namespace Details {
	class IRandomNumberGenerator;
}
namespace Messages {
	struct Error;
	struct KeyStatus;
	struct RequestSessionInitiation;
	struct SessionStartRequest;
	struct SessionStartResponse;
	struct SetKeys;
}
class SecurityLayer
{
public :
	SecurityLayer(
		  boost::asio::io_context &io_context
		, Config config
		, Details::IRandomNumberGenerator &random_number_generator
		);
	virtual ~SecurityLayer() = default;
	
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

	unsigned int getStatistic(Statistics statistic) noexcept;

public : // public API for testing purposes
	enum State {
		  initial__
		, expect_session_start_request__
		, expect_session_start_response__
		, expect_set_keys__
		, expect_session_ack__
		, active__
		};

	State getState() const noexcept { return state_; }

protected :
	/* Library hooks. */
	virtual KeyWrapAlgorithm getPreferredKeyWrapAlgorithm() const noexcept;
	virtual MACAlgorithm getPreferredMACAlgorithm() const noexcept;

protected :
	virtual void reset() noexcept = 0;

	void setOutgoingSPDU(
		  boost::asio::const_buffer const &spdu
		, boost::asio::steady_timer::duration const &timeout = std::chrono::milliseconds(0)
		) noexcept;
	void setState(State state) noexcept { state_ = state; }

	void discardAPDU() noexcept;
	void queueAPDU(boost::asio::const_buffer const &apdu) noexcept;

	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept = 0;

	void incrementSEQ() noexcept { seq_++; }
	std::uint32_t getSEQ() const noexcept { return seq_; }
	void setSEQ(std::uint32_t seq) noexcept { seq_ = seq; }

	boost::asio::const_buffer formatAuthenticatedAPDU(boost::asio::const_buffer const &apdu) noexcept;
	boost::asio::const_buffer format(Messages::RequestSessionInitiation const &rsi) noexcept;
	boost::asio::const_buffer format(Messages::SessionStartRequest const &ssr) noexcept;
	boost::asio::const_buffer format(Messages::SessionStartResponse const &ssr, boost::asio::const_buffer const &nonce) noexcept;
	boost::asio::const_buffer format(Messages::SetKeys const &sk) noexcept;
	boost::asio::const_buffer format(Messages::KeyStatus const &ks) noexcept;
	boost::asio::const_buffer format(Messages::Error const &e) noexcept;

	void incrementStatistic(Statistics statistics) noexcept;

	virtual void rxRequestSessionInitiation(uint32_t incoming_seq, boost::asio::const_buffer const &spdu) noexcept;
	virtual void rxSessionStartRequest(uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &spdu) noexcept;
	virtual void rxSessionStartResponse(uint32_t incoming_seq, Messages::SessionStartResponse const &incoming_ssr, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &spdu) noexcept;

	Config const config_;
	Details::IRandomNumberGenerator &random_number_generator_;

private :
	void parseIncomingSPDU() noexcept;

	State state_ = initial__;
	boost::asio::const_buffer outgoing_apdu_;
	boost::asio::const_buffer outgoing_spdu_;
	boost::asio::const_buffer incoming_apdu_;
	boost::asio::const_buffer incoming_spdu_;

	unsigned char incoming_spdu_buffer_[Config::max_spdu_size__];
	unsigned char outgoing_apdu_buffer_[Config::max_apdu_size__];
	unsigned char outgoing_spdu_buffer_[Config::max_apdu_size__];
	unsigned int outgoing_spdu_size_;

	boost::asio::steady_timer timeout_;

	std::uint32_t seq_ = 0;

	unsigned int statistics_[static_cast< int >(Statistics::statistics_count__)];
};
}

#endif


