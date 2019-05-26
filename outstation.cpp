#include "outstation.hpp"
#include "messages.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Outstation::Outstation(
	  boost::asio::io_context &io_context
	, Config config
	)
	: SecurityLayer(io_context, config)
{ /* no-op */ }

/*virtual */void Outstation::reset() noexcept/* override*/
{
	SecurityLayer::reset();
}
/*virtual */void Outstation::onPostAPDU(boost::asio::const_buffer const &apdu) noexcept/* override*/
{
	//TODO check if there are session keys and, if so, use them to send the APDU along. Otherwise, go through the state
	//     machine. The state machine maybe setting up new keys, but if we have keys, we might as well use them.
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
		sendAuthenticatedAPDU(apdu);
		break;
	default :
		assert(!"unexpected state");
	}
}

/*virtual */void Outstation::rxSessionStartRequest(uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr) noexcept/* override*/
{
#ifdef OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
	static_assert(OPTION_MASTER_SETS_KWA_AND_MAL, "The Master-provided KWA and MAL can only be hints if it actually sets them");
	KeyWrapAlgorithm suggested_key_wrap_algorithm;
	MACAlgorithm suggested_mac_algorithm;
#endif
	Messages::SessionStartResponse response;

	switch (getState())
	{
	case initial__ :
		// fall through
	case expect_session_start_request__ :
		// check the values in the session start request to see if I can live with them
		if (incoming_ssr.version_ == 6)
		{ /* OK so far */ }
		else
		{
			send(Messages::Error(Messages::Error::unsupported_version__));
			break;
		}
		if (incoming_ssr.flags_ == 0)
		{ /* still OK */ }
		else
		{
			send(Messages::Error(Messages::Error::unexpected_flags__));
			break;
		}
#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
		if (acceptKeyWrapAlgorithm(static_cast< KeyWrapAlgorithm >(incoming_ssr.key_wrap_algorithm_)))
		{
#ifdef OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.key_wrap_algorithm_ = incoming_ssr.key_wrap_algorithm_;
#endif
		}
		else
		{
#ifdef OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.key_wrap_algorithm_ = getPreferredKeyWrapAlgorithm();
#endif

		}
		if (acceptMACAlgorithm(static_cast< MACAlgorithm >(incoming_ssr.mac_algorithm_)))
		{
#ifdef OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.mac_algorithm_ = incoming_ssr.mac_algorithm_;
#endif
		}
		else
		{
#ifdef OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
			response.mac_algorithm_ = getPreferredMACAlgorithm();
#endif

		}
#else
		response.key_wrap_algorithm_ = getPreferredKeyWrapAlgorithm();
		response.mac_algorithm_ = getPreferredMACAlgoithm();
#endif
		// if so, add them to the session builder, and add the buffer to the session builder for later hashing
		// otherwise, send back an appropriate error message or, if the values I don't like are only hints, send a response with values I do like.
	case expect_set_keys__ :
		//TODO if the sequence number is the same, re-send our response
		//     if the sequence number is one higher, and values for the KWA and the MAL from the Master are hints, treat them 
		//     otherwise increment appropriate statistics and ignore
	case active__ :
		//TODO keep our keys, but start a new session key setup
	default :
		assert(!"unexpected state");
	}
//version_ = 6;
//std::uint8_t flags_ = 0;
//#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
//key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
//mac_algorithm_ = 4/* HMAC SHA256 T16*/;
//#endif
//session_key_change_interval_ = 60/*one hour*/;
//session_key_change_count_ = 4096;
}

/*virtual */bool Outstation::acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept
{
	return true;
}

/*virtual */bool Outstation::acceptMACAlgorithm(KeyWrapAlgorithm incoming_mal) const noexcept
{
	return true;
}

void Outstation::sendRequestSessionInitiation() noexcept
{
	send(Messages::RequestSessionInitiation());
}
}




