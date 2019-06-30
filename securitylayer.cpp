#include "securitylayer.hpp"
#include "exceptions/contract.hpp"
#include "messages.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SecurityLayer::SecurityLayer(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	)
	: config_(config)
	, random_number_generator_(random_number_generator)
	, timeout_(io_context)
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
	case expect_session_ack__ :
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

/*virtual */bool SecurityLayer::acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept
{
	return true;
}

/*virtual */bool SecurityLayer::acceptMACAlgorithm(MACAlgorithm incoming_mal) const noexcept
{
	return true;
}

/*virtual */KeyWrapAlgorithm SecurityLayer::getPreferredKeyWrapAlgorithm() const noexcept
{
	return KeyWrapAlgorithm::nist_sp800_38f_aes_256__;
}

/*virtual */MACAlgorithm SecurityLayer::getPreferredMACAlgorithm() const noexcept
{
	return MACAlgorithm::hmac_sha_256_truncated_16__;
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

boost::asio::const_buffer SecurityLayer::formatAuthenticatedAPDU(boost::asio::const_buffer const &apdu) noexcept
{
	return const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::RequestSessionInitiation const &rsi) noexcept
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
	// // NOTE: if we add anything to the structure, it should be copied in here

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::SessionStartRequest const &ssr) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= 8 + sizeof(ssr), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x01;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_start_request__);
	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	assert(outgoing_spdu_size_ == 8);

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &ssr, sizeof(ssr));
	outgoing_spdu_size_ += sizeof(ssr);
	assert(outgoing_spdu_size_ == 8 + sizeof(ssr));

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::SessionStartResponse const &ssr, const_buffer const &nonce) noexcept
{
	pre_condition(sizeof(outgoing_spdu_buffer_) >= 8 + sizeof(ssr) + nonce.size());
	
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x01;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_start_response__);
	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	assert(outgoing_spdu_size_ == 8);

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &ssr, sizeof(ssr));
	outgoing_spdu_size_ += sizeof(ssr);
	assert(outgoing_spdu_size_ == 8 + sizeof(ssr));

	assert(ssr.challenge_data_length_ == nonce.size());
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, nonce.data(), nonce.size());
	outgoing_spdu_size_ += nonce.size();

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::SetKeys const &sk) noexcept
{
	return const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::KeyStatus const &ks) noexcept
{
	return const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::Error const &e) noexcept
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

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

void SecurityLayer::incrementStatistic(Statistics statistic) noexcept
{
	++statistics_[static_cast< int >(statistic)];
}

unsigned int SecurityLayer::getStatistic(Statistics statistic) noexcept
{
	return statistics_[static_cast< int >(statistic)];
}

/*virtual */void SecurityLayer::rxRequestSessionInitiation(uint32_t incoming_seq, boost::asio::const_buffer const &spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxSessionStartRequest(uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxSessionStartResponse(uint32_t incoming_seq, Messages::SessionStartResponse const &incoming_ssr, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}

void SecurityLayer::parseIncomingSPDU() noexcept
{
	unsigned char const *incoming_spdu_data(static_cast< unsigned char const* >(incoming_spdu_.data()));
	unsigned char const *curr(incoming_spdu_data);
	unsigned char const *const end(curr + incoming_spdu_.size());

	if (distance(curr, end) < 8)
	{
		const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
		setOutgoingSPDU(response_spdu);
		incrementStatistic(Statistics::error_messages_sent__);
		incrementStatistic(Statistics::total_messages_sent__);
	}
	else
	{ /* it's at least big enough to be a valid SPDU */ }

	static const unsigned char preamble__[] = { 0xC0, 0x80, 0x01 };
	if (!equal(curr, curr + sizeof(preamble__), preamble__))
	{
		const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
		setOutgoingSPDU(response_spdu);
		incrementStatistic(Statistics::error_messages_sent__);
		incrementStatistic(Statistics::total_messages_sent__);
	}
	else
	{ /* preamble is OK */ }
	curr += 3;

	unsigned char const incoming_function_code(*curr++);

	uint32_t incoming_seq;
	memcpy(&incoming_seq, curr, 4/*size of the sequence number*/);
	curr += 4;

	switch (incoming_function_code)
	{
	case static_cast< uint8_t >(Message::request_session_initiation__) :
		rxRequestSessionInitiation(incoming_seq, incoming_spdu_);
		break;
	case static_cast< uint8_t >(Message::session_start_request__) :
		// check the SPDU size to see if it's big enough to hold a SessionStartRequest message
		// if so, parse into a SessionStartRequest object and call rxSessionStartRequest(incoming_seq, incoming_ssr);
		if (incoming_spdu_.size() == sizeof(Messages::SessionStartRequest) + 8/*header size*/)
		{
			Messages::SessionStartRequest incoming_ssr;
			assert(distance(curr, end) == sizeof(incoming_ssr));
			incoming_ssr.version_ = *curr++;
			if (incoming_ssr.version_ != 6)
			{
				const_buffer response_spdu(format(Messages::Error(Messages::Error::unsupported_version__)));
				setOutgoingSPDU(response_spdu);
				incrementStatistic(Statistics::error_messages_sent__);
				incrementStatistic(Statistics::total_messages_sent__);
				break;
			}
			else
			{ /* all is well as far as the version is concerned */ }
 			incoming_ssr.flags_ = *curr++;
    
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
			incoming_ssr.key_wrap_algorithm_ = *curr++;
			incoming_ssr.mac_algorithm_ = *curr++;
#endif
			memcpy(&incoming_ssr.session_key_change_interval_, curr, 4);
			curr += 4;
			memcpy(&incoming_ssr.session_key_change_count_, curr, 2);
			curr += 2;
			assert(curr == end);
			rxSessionStartRequest(incoming_seq, incoming_ssr, incoming_spdu_);
		}
		else
		{
			const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
		}
		break;
	case static_cast< uint8_t >(Message::session_start_response__) :
	{
		unsigned int const min_expected_spdu_size(8/*header size*/ + sizeof(Messages::SessionStartResponse) + Config::min_nonce_size__);
		unsigned int const max_expected_spdu_size(8/*header size*/ + sizeof(Messages::SessionStartResponse) + Config::max_nonce_size__);
		if ((incoming_spdu_.size() >= min_expected_spdu_size) && (incoming_spdu_.size() <= max_expected_spdu_size))
		{
			Messages::SessionStartResponse incoming_ssr;
			assert(static_cast< size_t >(distance(curr, end)) > sizeof(incoming_ssr));
			memcpy(&incoming_ssr, curr, sizeof(incoming_ssr));
			curr += sizeof(incoming_ssr);

			if (incoming_ssr.challenge_data_length_ == distance(curr, end))
			{
				const_buffer nonce(curr, distance(curr, end));
				rxSessionStartResponse(incoming_seq, incoming_ssr, nonce, incoming_spdu_);
			}
			else
			{
				const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
				setOutgoingSPDU(response_spdu);
				incrementStatistic(Statistics::error_messages_sent__);
				incrementStatistic(Statistics::total_messages_sent__);
			}
		}
		else
		{
			const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
		}

		// check the SPDU size to see if it's big enough to hold a SessionStartResponse message
		// if so, parse into a SessionStartResponse object and call rxSessionStartResponse(incoming_seq, incoming_ssr);
		break;
	}
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
		const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
		setOutgoingSPDU(response_spdu);
		incrementStatistic(Statistics::error_messages_sent__);
		incrementStatistic(Statistics::total_messages_sent__);
	}
}
}


