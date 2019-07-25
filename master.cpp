#include "master.hpp"
#include "messages.hpp"
#include <chrono>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Master::Master(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	)
	: SecurityLayer(io_context, config, random_number_generator)
#if defined(OPTION_ITERATE_KWA_AND_MAL) && OPTION_ITERATE_KWA_AND_MAL
	, kwa_index_(0)
	, mal_index_(0)
#endif
	, session_builder_(io_context, random_number_generator)
{ /* no-op */ }

/*virtual */void Master::reset() noexcept/* override*/
{
#if defined(OPTION_ITERATE_KWA_AND_MAL) && OPTION_ITERATE_KWA_AND_MAL
	kwa_index_ = 0;
	mal_index_ = 0;
#endif
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
	case expect_session_ack__ :
		/* no-op: re-sending SetSessionKeys messages is driven by its time-out and receiving
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
#if defined(OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION) && OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
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
	case expect_session_ack__ :
	case active__ :
		incrementStatistic(Statistics::unexpected_messages__);
		break;
	default :
		assert(!"Unexpected state");
	}
}

/*virtual */void Master::rxSessionStartResponse(
	  uint32_t incoming_seq
	, Messages::SessionStartResponse const &incoming_ssr
	, boost::asio::const_buffer const &nonce
	, boost::asio::const_buffer const &spdu
	) noexcept/* override*/
{
	switch (getState())
	{
	case expect_session_start_response__ :
	{
		session_builder_.setSessionStartResponse(spdu, nonce);
		//TODO check sequence number
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
#if defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS
		// check if the proposed algorithms concur.
#if defined(OPTION_ITERATE_KWA_AND_MAL) && OPTION_ITERATE_KWA_AND_MAL
		// if the proposed algorithms don't concur and we iterate, see if theirs is acceptable. If so, take it, otherwise iterate

#else
		// if the proposed algorithms don't concur and we don't iterate, see if theirs is acceptable. If so, take it, otherwise fail
#endif
#endif
#else		// if the Outstation provides a set of algorithms, and we don't, take theirs
		KeyWrapAlgorithm incoming_kwa(static_cast<KeyWrapAlgorithm>(incoming_ssr.key_wrap_algorithm_));
		MACAlgorithm incoming_mal(static_cast<MACAlgorithm>(incoming_ssr.mac_algorithm_));
		if (acceptKeyWrapAlgorithm(incoming_kwa) && acceptMACAlgorithm(incoming_mal))
		{
			session_builder_.setKeyWrapAlgorithm(incoming_kwa);
			session_builder_.setMACAlgorithm(incoming_mal);
		}
		else
		{
			//TODO log this: unacceptable algorithm proposed
			return;
		}
#endif
		session_builder_.setSessionKeyChangeInterval(std::chrono::seconds(incoming_ssr.session_key_change_interval_));
		session_builder_.setSessionKeyChangeCount(incoming_ssr.session_key_change_count_);
		assert(incoming_ssr.challenge_data_length_ == nonce.size());

		auto wrapped_key_data(session_builder_.createWrappedKeyData(mutable_buffer(buffer_, sizeof(buffer_))));
		Messages::SetSessionKeys set_session_keys;
		set_session_keys.key_wrap_data_length_ = wrapped_key_data.size();
		const_buffer const spdu(format(set_session_keys, wrapped_key_data));
		setOutgoingSPDU(spdu, std::chrono::milliseconds(config_.set_session_keys_timeout_));
		setState(expect_session_ack__);
		break;
	}
	case expect_session_ack__ :
		/* This is probably the response we got previously. Check if it it's identical and, if so, repeat the response. 
		 * Otherwise, it's an unexpected message. */
	case initial__ :
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
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
#if defined(OPTION_ITERATE_KWA_AND_MAL) && OPTION_ITERATE_KWA_AND_MAL
	if (kwa_index_ < config_.key_wrap_algorithm_count_)
	{
		ssr.key_wrap_algorithm_ = config_.getKeyWrapAlgorithm(kwa_index_);
	}
	else
	{	// we've run out of key-wrap algorithms to suggest
		//TODO TO DISCUSS: increment a stat for this? Log?
		return;
	}
	if (mal_index_ < config_.mac_algorithm_count_)
	{
		ssr.mac_algorithm_ = config_.getMACAlgorithm(mal_index_);
	}
	else
	{	// we've run out of MAC algorithms to suggest
		//TODO TO DISCUSS: increment a stat for this? Log?
		return;
	}
#else
	ssr.key_wrap_algorithm_ = config_.key_wrap_algorithm_;
	ssr.mac_algorithm_ = config_.mac_algorithm_;
#endif
	//TODO set the proposed algorithm in the session builder
	session_builder_.setKeyWrapAlgorithm(static_cast< KeyWrapAlgorithm >(ssr.key_wrap_algorithm_));
	session_builder_.setMACAlgorithm(static_cast< MACAlgorithm >(ssr.mac_algorithm_));
#endif
	ssr.session_key_change_interval_ = config_.session_key_change_interval_;
	ssr.session_key_change_count_ = config_.session_key_change_count_;

	const_buffer const spdu(format(ssr));
	setOutgoingSPDU(spdu, std::chrono::milliseconds(config_.session_start_request_timeout_));
	session_builder_.setSessionStartRequest(spdu);
	// increment stats
	
}
}





