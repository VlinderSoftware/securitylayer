/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#ifndef dnp3sav6_securitylayer_hpp
#define dnp3sav6_securitylayer_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <boost/asio.hpp>
#include "config.hpp"
#include "exceptions.hpp"
#include "statistics.hpp"
#include "keywrapalgorithm.hpp"
#include "aeadalgorithm.hpp"
#include "session.hpp"
#include "details/seqvalidator.hpp"
#include "details/direction.hpp"

namespace DNP3SAv6 {
namespace Details {
	class IRandomNumberGenerator;
}
namespace Messages {
	struct Error;
	struct SecureMessage;
	struct SessionInitiation;
	struct SessionKeyChangeRequest;
	struct SessionKeyChangeResponse;
	struct SessionStartRequest;
	struct SessionStartResponse;
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
        , spdu_ready__
        , apdu_ready__
		};

	// signal link loss (from lower layers)
	void onLinkLost() noexcept;
	// signal application reset (from application layer)
	void onApplicationReset() noexcept;
	// signal an application layer timeout
	void onApplicationLayerTimeout() noexcept;
    // cancel a pending APDU for any reason
    void cancelPendingAPDU() noexcept;

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
		, expect_session_key_change_request__
		, expect_session_key_change_response__
		, active__
		};

	State getState() const noexcept { return state_; }

protected:
	/* Library hooks.
	 * NOTE: the incoming stuff is not authenticated yet. DO NOT take any descisions based on this incoming data. Only
	 *       tell the implementation if you'd be willing, according to your configuration, to accept the proposed
	 *       key-wrap algorithm and MAC algorithm. DO NOT presume that these will actually be used for anything, so
	 *       don't start allocating resources etc. Also don't log everything: that can be used as DOS attacks on your
	 *       logs. The fewer side-effects the better. */
	virtual bool acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept;
	virtual bool acceptMACAlgorithm(AEADAlgorithm incoming_mal) const noexcept;

protected :
    virtual Details::Direction getIncomingDirection() const noexcept = 0;
    virtual Details::Direction getOutgoingDirection() const noexcept = 0;

	virtual void reset() noexcept = 0;

	void setOutgoingSPDU(
		  boost::asio::const_buffer const &spdu
		, boost::asio::steady_timer::duration const &timeout = std::chrono::milliseconds(0)
		) noexcept;
	void setState(State state) noexcept { state_ = state; }

	void discardAPDU() noexcept;
	void queueAPDU(boost::asio::const_buffer const &apdu) noexcept;
	void clearPendingAPDU() noexcept;

	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept = 0;

	void incrementSEQ() noexcept { seq_++; }
	std::uint32_t getSEQ() const noexcept { return seq_; }
	void setSEQ(std::uint32_t seq) noexcept { seq_ = seq; }

	boost::asio::const_buffer formatSecureMessage(Details::Direction direction, boost::asio::const_buffer const &apdu) noexcept;
	boost::asio::const_buffer format(Messages::SessionInitiation const &rsi) noexcept;
	boost::asio::const_buffer format(Messages::SessionStartRequest const &ssr) noexcept;
	boost::asio::const_buffer format(std::uint32_t seq, Messages::SessionStartResponse const &ssr, boost::asio::const_buffer const &nonce) noexcept;
	boost::asio::const_buffer format(Messages::SessionKeyChangeRequest const &sk, boost::asio::const_buffer const &wrapped_key_data) noexcept;
	boost::asio::const_buffer format(std::uint32_t seq, Messages::SessionKeyChangeResponse const &sc, boost::asio::const_buffer const &digest, unsigned int authentication_tag_length) noexcept;
	boost::asio::const_buffer format(Messages::Error const &e) noexcept;
	boost::asio::const_buffer format(std::uint32_t seq, Messages::Error const &e) noexcept;

	void incrementStatistic(Statistics statistics) noexcept;

	virtual void rxSessionInitiation(std::uint32_t incoming_seq, boost::asio::const_buffer const &incoming_spdu) noexcept;
	virtual void rxSessionStartRequest(std::uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &incoming_spdu) noexcept;
	virtual void rxSessionStartResponse(std::uint32_t incoming_seq, Messages::SessionStartResponse const &incoming_ssr, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &incoming_spdu) noexcept;
    virtual void rxSessionKeyChangeRequest(std::uint32_t incoming_seq, Messages::SessionKeyChangeRequest const& incoming_ssk, boost::asio::const_buffer const& incoming_key_wrap_data, boost::asio::const_buffer const& incoming_spdu) noexcept;
    virtual void rxSessionKeyChangeResponse(std::uint32_t incoming_seq, Messages::SessionKeyChangeResponse const &incoming_sc, boost::asio::const_buffer const &incoming_mac, boost::asio::const_buffer const& incoming_spdu) noexcept;
    virtual void rxSecureMessage(std::uint32_t incoming_seq, boost::asio::const_buffer const& incoming_nonce, boost::asio::const_buffer const& incoming_associated_data, boost::asio::const_buffer const& incoming_payload, boost::asio::const_buffer const& incoming_spdu) noexcept;

    void setSession(Session const &session) noexcept { session_ = session; }
    Session& getSession() noexcept { return session_; }

	Config const config_;
	Details::IRandomNumberGenerator &random_number_generator_;
    Details::SEQValidator seq_validator_;

private :
	void parseIncomingSPDU() noexcept;

	State state_ = initial__;
	boost::asio::const_buffer outgoing_apdu_;
	boost::asio::const_buffer outgoing_spdu_;
	boost::asio::const_buffer incoming_apdu_;
	boost::asio::const_buffer incoming_spdu_;

	unsigned char incoming_spdu_buffer_[Config::max_spdu_size__];
	unsigned char incoming_apdu_buffer_[Config::max_spdu_size__/*yes, SPDU size -- we use this buffer to decrypt into*/];
	unsigned char outgoing_apdu_buffer_[Config::max_apdu_size__];
	unsigned char outgoing_spdu_buffer_[Config::max_apdu_size__];
	unsigned int outgoing_spdu_size_;

	boost::asio::steady_timer timeout_;

	std::uint32_t seq_ = 0;

	unsigned int statistics_[static_cast< int >(Statistics::statistics_count__)];

    Session session_;
};
}

#endif


