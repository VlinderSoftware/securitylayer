#include "outstation.hpp"
#include "messages.hpp"
#include "details/irandomnumbergenerator.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Outstation::Outstation(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	)
	: SecurityLayer(io_context, config, random_number_generator)
{ /* no-op */ }

/*virtual */void Outstation::reset() noexcept/* override*/
{
	SecurityLayer::reset();
}
/*virtual */void Outstation::onPostAPDU(boost::asio::const_buffer const &apdu) noexcept/* override*/
{
	//TODO check if there are session keys and, if so, use them to send the APDU along. Otherwise, go through the state
	//     machine. The state machine maybe setting up new keys, but if we have keys, we might as well use them.
	boost::asio::const_buffer spdu;
	switch (getState())
	{
	case initial__ :
		incrementSEQ();
	case expect_session_start_request__ :
		sendRequestSessionInitiation();
		setState(expect_session_start_request__);
		break;
	case expect_set_keys__ :
		/* no-op: sending SessionStartResponse is drive by its time-out or receiving 
		 * SessionStartRequest messages, not by APDUs */
		break;
	case active__ :
		incrementSEQ();
		spdu = formatAuthenticatedAPDU(apdu);
		//HERE
		break;
	default :
		assert(!"unexpected state");
	}
}

/*virtual */void Outstation::rxSessionStartRequest(uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &incoming_spdu) noexcept/* override*/
{
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
	static_assert(OPTION_MASTER_SETS_KWA_AND_MAL, "The Master-provided KWA and MAL can only be hints if it actually sets them");
#endif
	Messages::SessionStartResponse response;

	const_buffer response_spdu;
	switch (getState())
	{
	case initial__ :
		// fall through
	case expect_session_start_request__ :
	{
		// check the values in the session start request to see if I can live with them
		if (incoming_ssr.version_ == 6)
		{ /* OK so far */ }
		else
		{
			response_spdu = format(Messages::Error(Messages::Error::unsupported_version__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		if (incoming_ssr.flags_ == 0)
		{ /* still OK */ }
		else
		{
			response_spdu = format(Messages::Error(Messages::Error::unexpected_flags__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		session_builder_.setSessionStartRequest(incoming_spdu);
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
		if (acceptKeyWrapAlgorithm(static_cast< KeyWrapAlgorithm >(incoming_ssr.key_wrap_algorithm_)))
		{
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.key_wrap_algorithm_ = incoming_ssr.key_wrap_algorithm_;
#endif
		}
		else
		{
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.key_wrap_algorithm_ = static_cast< std::uint8_t >(getPreferredKeyWrapAlgorithm());
#else
			response_spdu = format(Messages::Error(Messages::Error::unsupported_keywrap_algorithm__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			return;
#endif
		}
		if (acceptMACAlgorithm(static_cast< MACAlgorithm >(incoming_ssr.mac_algorithm_)))
		{
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.mac_algorithm_ = incoming_ssr.mac_algorithm_;
#endif
		}
		else
		{
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.mac_algorithm_ = static_cast< uint8_t >(getPreferredMACAlgorithm());
#else
			response_spdu = format(Messages::Error(Messages::Error::unsupported_mac_algorithm__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			return;
#endif

		}
#else
		response.key_wrap_algorithm_ = static_cast< std::uint8_t >(getPreferredKeyWrapAlgorithm());
		response.mac_algorithm_ = static_cast< std::uint8_t >(getPreferredMACAlgorithm());
#endif
		response.session_key_change_interval_ = config_.session_key_change_interval_;
		response.session_key_change_count_ = config_.session_key_change_count_;

		assert(config_.nonce_size_ <= config_.max_nonce_size__);
		boost::asio::mutable_buffer nonce_buffer(nonce_, config_.nonce_size_);
		random_number_generator_.generate(nonce_buffer);
		response.challenge_data_length_ = config_.nonce_size_;

		response_spdu = format(response, nonce_buffer);
		
		session_builder_.setSessionStartResponse(response_spdu, nonce_buffer);
		setState(State::expect_set_keys__);
		setOutgoingSPDU(response_spdu, std::chrono::milliseconds(config_.session_start_response_timeout_));
		incrementStatistic(Statistics::total_messages_sent__);
		return;
	}
	case expect_set_keys__ :
		//TODO if the sequence number is the same, re-send our response -- make sure to use the same nonce
		//     if the sequence number is one higher, and values for the KWA and the MAL from the Master are hints, treat them 
		//     otherwise increment appropriate statistics and ignore
	case active__ :
		//TODO keep our keys, but start a new session key setup
	default :
		assert(!"unexpected state");
	}
//session_key_change_interval_ = 60/*one hour*/;
//session_key_change_count_ = 4096;
//send the response_spdu HERE!!
}

/*virtual */bool Outstation::acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept
{
	return true;
}

/*virtual */bool Outstation::acceptMACAlgorithm(MACAlgorithm incoming_mal) const noexcept
{
	return true;
}

void Outstation::sendRequestSessionInitiation() noexcept
{
	const_buffer spdu(format(Messages::RequestSessionInitiation()));
	setOutgoingSPDU(spdu, std::chrono::milliseconds(config_.request_session_initiation_timeout_));
	incrementStatistic(Statistics::total_messages_sent__);
}
}




