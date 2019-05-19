#include "securitylayer.hpp"
#include "exceptions/contract.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SecurityLayer::SecurityLayer(
	  boost::asio::io_context &io_context
	, TransportFunction *transport_function
	, ApplicationLayer *application_layer
	)
	: transport_function_(transport_function)
	, application_layer_(application_layer)
	, timeout_(io_context)
{
	pre_condition(transport_function);
	pre_condition(application_layer);
}

void SecurityLayer::onLinkLost() noexcept
{
	reset();
}
void SecurityLayer::onApplicationReset() noexcept
{
	reset();
}
void SecurityLayer::onAPDUTimeout() noexcept
{
	switch (state_)
	{
	case initial__ :
		break;
	case expect_session_start_request__ :
		reset();
		break;
	case expect_session_start_response__ :
	case expect_set_keys__ :
	case expect_key_status__ :
		discardAPDU();
		// no state change
		break;
	case active__ :
		// no-op
		break;
	}
}
void SecurityLayer::postAPDU(const_buffer const &apdu) noexcept
{
	pre_condition(apdu.size() <= sizeof(outgoing_apdu_buffer_));

	// if any APDU is pending, it must be discarded: we cannot have more than one APDU at a 
	// time and the Application Layer must be in charge of what gets sent.
	discardAPDU();
	queueAPDU(apdu);
	onPostAPDU(apdu);
}
void SecurityLayer::postSPDU(const_buffer const &spdu) noexcept
{
	pre_condition(spdu.size() <= sizeof(incoming_spdu_buffer_));

	incrementStatistic(Statistics::total_messages_received__);

	memcpy(incoming_spdu_buffer_, spdu.data(), spdu.size());
	incoming_spdu_ = const_buffer(incoming_spdu_buffer_, spdu.size());

	parseIncomingSPDU();
}

bool SecurityLayer::pollAPDU() const noexcept
{
	return incoming_apdu_.size() != 0;
}
bool SecurityLayer::pollSPDU() const noexcept
{
	return outgoing_spdu_.size() != 0;
}

const_buffer SecurityLayer::getAPDU() noexcept
{
	const_buffer const retval(incoming_apdu_);
	incoming_apdu_ = const_buffer();

	return retval;
}
const_buffer SecurityLayer::getSPDU() noexcept
{
	const_buffer const retval(outgoing_spdu_);
	outgoing_spdu_= const_buffer();

	return retval;
}

void SecurityLayer::reset() noexcept
{
	discardAPDU();
	state_ = initial__;
	incoming_apdu_ = const_buffer();
	incoming_spdu_ = const_buffer();
	outgoing_apdu_ = const_buffer();
	outgoing_spdu_ = const_buffer();
}

void SecurityLayer::setOutgoingSPDU(
	  boost::asio::const_buffer const &spdu
	, boost::asio::steady_timer::duration const &timeout/* = std::chrono::milliseconds(0)*/
	) noexcept
{
	timeout_.expires_after(timeout);
	outgoing_spdu_ = spdu;
}

void SecurityLayer::discardAPDU() noexcept
{
	if (outgoing_apdu_.size())
	{
		incrementStatistic(Statistics::discarded_messages__);
	}
	else
	{ /* no pending APDU - nothing to increment */ }
	outgoing_apdu_ = const_buffer();
}

void SecurityLayer::queueAPDU(boost::asio::const_buffer const &apdu) noexcept
{
	memcpy(outgoing_apdu_buffer_, apdu.data(), apdu.size());
	outgoing_apdu_ = const_buffer(outgoing_apdu_buffer_, apdu.size());
}

void SecurityLayer::parseIncomingSPDU() noexcept
{
//NEXT
}
}


