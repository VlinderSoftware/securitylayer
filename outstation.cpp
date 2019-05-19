#include "outstation.hpp"
#include "messages.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Outstation::Outstation(
	  boost::asio::io_context &io_context
	, Config config
	)
	: SecurityLayer(io_context)
	, config_(config)
{ /* no-op */ }

/*virtual */void Outstation::reset() noexcept/* override*/
{
	SecurityLayer::reset();
}
/*virtual */void Outstation::onPostAPDU(boost::asio::const_buffer const &apdu) noexcept/* override*/
{
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

void Outstation::sendRequestSessionInitiation() noexcept
{
	static_assert(
		  sizeof(buffer_) >= sizeof(Messages::RequestSessionInitiation)
		, "message too larget for SPDU"
		);
	Messages::RequestSessionInitiation message;
	message.type_ = static_cast< decltype(message.type_) >(Message::request_session_initiation__);
	message.seq_ = getSEQ();

	memcpy(buffer_, &message, sizeof(message));
	setOutgoingSPDU(
		  const_buffer(buffer_, sizeof(message))
		, std::chrono::milliseconds(config_.request_session_initiation_timeout_)
		);
	incrementStatistic(Statistics::total_messages_sent__);
}
}




