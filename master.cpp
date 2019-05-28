#include "master.hpp"
#include "messages.hpp"
#include "config.h"

#include <chrono>

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Master::Master(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	)
	: SecurityLayer(io_context, config, random_number_generator)
{ /* no-op */ }

/*virtual */void Master::reset() noexcept/* override*/
{
	SecurityLayer::reset();
}

/*virtual */void Master::onPostAPDU(boost::asio::const_buffer const &apdu) noexcept/* override*/
{
	switch (getState())
	{
	case initial__ :
		incrementSEQ();
		sendSessionStartRequest();
		setState(expect_session_start_response__);
		break;
	case expect_session_start_response__ :
		/* no-op: re-sending the SessionStartRequest message is driven by its time-out, not
		 * the APDUs */
		break;
	case expect_key_status__ :
		/* no-op: re-sending SetKeys messages is driven by its time-out and receiving
		 * SessionStartResponse messages, not by APDUs. */
		break;
	case active__ :
	{
		incrementSEQ();
		const_buffer spdu(formatAuthenticatedAPDU(apdu));
		setOutgoingSPDU(spdu/* no time-out */);
		// no state change
		incrementStatistic(Statistics::total_messages_sent__);
		incrementStatistic(Statistics::authenticated_apdus_sent__);
		break;
	}
	default :
		assert(!"Unexpected state");
	}
}

/*virtual */void Master::rxRequestSessionInitiation(uint32_t incoming_seq, boost::asio::const_buffer const &spdu) noexcept/* override*/
{
	switch (getState())
	{
#ifdef OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
	case initial__ :
		incrementSEQ();
		// fall through
	case expect_session_start_response__ :
		sendSessionStartRequest();
		setState(expect_session_start_response__);
		break;
#else
	case expect_session_start_response__ :
		/* If the Outstation requested a session initiation and its SEQ is different than 
		 * ours, we ignore it and let the time-out handle re-sends. Otherwise, we re-send 
		 * and reset the time-out. Note that other than resetting the time-out, and 
		 * sending a few bytes over the link, this has no effect on us or our state 
		 * machine. */
		if (incoming_seq != getSEQ())
		{
			incrementStatistic(Statistics::unexpected_messages__);
			break;
		}
		else
		{ /* SEQ is OK */ }
		sendSessionStartRequest();
		setState(expect_session_start_response__);
		break;
	case initial__ :
		/* If the incoming SEQ is smaller than or equal to our own, we can't use it, but we 
		 * can still initiate the session. If it's greater than our own, we can use it, if 
		 * it's reasonable. We'll call it reasonable if it's less than half the range (i.e. 
		 * the most significant bit is not set). */
		static_assert(sizeof(incoming_seq) == 4, "unexpected size for seq");
		if ((incoming_seq > getSEQ()) && ((incoming_seq & 0x80000000) == 0))
		{
			setSEQ(incoming_seq);
		}
		else
		{
			incrementSEQ();
		}
		sendSessionStartRequest();
		setState(expect_session_start_response__);
		break;
#endif
	case expect_key_status__ :
	case active__ :
		incrementStatistic(Statistics::unexpected_messages__);
		break;
	default :
		assert(!"Unexpected state");
	}
}

void Master::sendSessionStartRequest() noexcept
{
	Messages::SessionStartRequest ssr;
	assert(ssr.version_ == 6);
	assert(ssr.flags_ == 0);
#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
	ssr.key_wrap_algorithm_ = config_.key_wrap_algorithm_;
	ssr.mac_algorithm_ = config_.mac_algorithm_;
#endif
	ssr.session_key_change_interval_ = config_.session_key_change_interval_;
	ssr.session_key_change_count_ = config_.session_key_change_count_;

	const_buffer const spdu(format(ssr));
	setOutgoingSPDU(spdu, std::chrono::milliseconds(config_.session_start_request_timeout_));
	// increment stats
	
}
}





