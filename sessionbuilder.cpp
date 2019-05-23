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
	switch (getState())
	{
	case initial__ :
		// fall through
	case expect_session_start_request__ :

	case expect_set_keys__ :
	case active__ :
	default :
		assert(!"unexpected state");
	}
version_ = 6;
std::uint8_t flags_ = 0;
#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
mac_algorithm_ = 4/* HMAC SHA256 T16*/;
#endif
session_key_change_interval_ = 60/*one hour*/;
session_key_change_count_ = 4096;
}

void Outstation::sendRequestSessionInitiation() noexcept
{
	send(Messages::RequestSessionInitiation());
}
}




