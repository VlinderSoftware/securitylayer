#include "securitylayer.hpp"
#include "exceptions/contract.hpp"
#include "messages.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SecurityLayer::SecurityLayer(
	  boost::asio::io_context &io_context
	, Config config
	)
	: timeout_(io_context)
	, config_(config)
{
	memset(statistics_, 0, sizeof(statistics_));
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

void SecurityLayer::sendAuthenticatedAPDU(boost::asio::const_buffer const &apdu) noexcept
{
}

void SecurityLayer::send(Messages::RequestSessionInitiation const &rsi) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= 8, "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x01;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::request_session_initiation__);
	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	assert(outgoing_spdu_size_ == 8);
	// NOTE: if we add anything to the structure, it should be copied in here
	setOutgoingSPDU(
		  const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_)
		, std::chrono::milliseconds(config_.session_start_request_timeout_)
		);
	incrementStatistic(Statistics::total_messages_sent__);
}

void SecurityLayer::send(Messages::SessionStartRequest const &ssr) noexcept
{
}

void SecurityLayer::send(Messages::SessionStartResponse const &ssr) noexcept
{
}

void SecurityLayer::send(Messages::SetKeys const &sk) noexcept
{
}

void SecurityLayer::send(Messages::KeyStatus const &ks) noexcept
{
}

void SecurityLayer::send(Messages::Error const &e) noexcept
{

	static_assert(sizeof(outgoing_spdu_buffer_) >= 8 + sizeof(e), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x01;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::request_session_initiation__);
	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	assert(outgoing_spdu_size_ == 8);
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &e, sizeof(e));
	outgoing_spdu_size_ += sizeof(e);
	assert(outgoing_spdu_size_ == 8 + sizeof(e));
	setOutgoingSPDU(
		  const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_)
		);
	incrementStatistic(Statistics::error_messages_sent__);
	incrementStatistic(Statistics::total_messages_sent__);
}

void SecurityLayer::incrementStatistic(Statistics statistic) noexcept
{
	++statistics_[static_cast< int >(statistic)];
}

unsigned int SecurityLayer::getStatistic(Statistics statistic) noexcept
{
	return statistics_[static_cast< int >(statistic)];
}

/*virtual */void SecurityLayer::rxRequestSessionInitiation(uint32_t incoming_seq) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}

void SecurityLayer::parseIncomingSPDU() noexcept
{
	if (incoming_spdu_.size() < 8)
	{
		send(Messages::Error(Messages::Error::invalid_spdu__));
	}
	else
	{ /* it's at least big enough to be a valid SPDU */ }
	static const unsigned char preamble__[] = { 0xC0, 0x80, 0x01 };
	if (memcmp(incoming_spdu_.data(), preamble__, sizeof(preamble__)) != 0)
	{
		send(Messages::Error(Messages::Error::invalid_spdu__));
	}
	else
	{ /* preamble is OK */ }
	uint32_t incoming_seq;
	memcpy(&incoming_seq, static_cast< unsigned char const * >(incoming_spdu_.data()) + 4/*offset to the sequence number*/, 4/*size of the sequence number*/);
	switch (static_cast< unsigned char const * >(incoming_spdu_.data())[3/*offset of the function code*/])
	{
	case static_cast< uint8_t >(Message::request_session_initiation__) :
		rxRequestSessionInitiation(incoming_seq);
		break;
	case static_cast< uint8_t >(Message::session_start_request__) :
		// check the SPDU size to see if it's big enough to hold a SessionStartRequest message
		// if so, parse into a SessionStartRequest object and call rxSessionStartRequest(incoming_seq, incoming_ssr);
		break;
	case static_cast< uint8_t >(Message::session_start_response__) :
		// check the SPDU size to see if it's big enough to hold a SessionStartResponse message
		// if so, parse into a SessionStartResponse object and call rxSessionStartResponse(incoming_seq, incoming_ssr);
		break;
	case static_cast< uint8_t >(Message::set_keys__) :
		// check the SPDU size to see if it's big enough to hold a SetKeys message
		// if so, parse into a SetKeys object and call rxSetKeys(incoming_seq, incoming_sk);
		break;
	case static_cast< uint8_t >(Message::key_status__) :
		// check the SPDU size to see if it's big enough to hold a KeyStatus message
		// if so, parse into a KeyStatus object and call rxkeyStatus(incoming_seq, incoming_ks);
		break;
	case static_cast< uint8_t >(Message::authenticated_apdu__) :
		// check the SPDU size to see if it's big enough to hold an AuthenticatedAPDU message
		// if so, parse into a AuthenticatedAPDU object and call rxAuthenticatedAPDU(incoming_seq, incoming_aa);
		break;
	case static_cast< uint8_t >(Message::error__) :
		// check the SPDU size to see if it's big enough to hold an Error message
		// if so, parse into a Error object and call rxError(incoming_seq, incoming_error);
		break;
	default :
		send(Messages::Error(Messages::Error::invalid_spdu__));
	}
}
}


