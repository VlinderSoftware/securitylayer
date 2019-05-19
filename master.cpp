#include "master.hpp"
#include "messages.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Master::Master(
	  boost::asio::io_context &io_context
	, TransportFunction *transport_function
	, ApplicationLayer *application_layer
	)
	: SecurityLayer(io_context, transport_function, application_layer)
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
		incrementSEQ();
		sendAuthenticatedAPDU(apdu);
		break;
	default :
		assert(!"Unexpected state");
	}
}

void Master::sendSessionStartRequest() noexcept
{
	static_assert(
		  sizeof(buffer_) >= sizeof(Messages::SessionStartRequest)
		, "message too larget for SPDU"
		);
	Messages::SessionStartRequest message;
	message.type_ = static_cast< decltype(message.type_) >(Message::session_start_request__);
	message.seq_ = getSEQ();

	memcpy(buffer_, &message, sizeof(message));
	setOutgoingSPDU(
		  const_buffer(buffer_, sizeof(message))
		, std::chrono::milliseconds(config_.session_start_request_timeout_)
		);
	incrementStatistic(Statistics::total_messages_sent__);
}
}





