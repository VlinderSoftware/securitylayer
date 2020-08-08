/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "securitylayer.hpp"
#include "exceptions/contract.hpp"
#include <openssl/crypto.h>
#include "messages.hpp"
#include "hmac.hpp"
#include "aead.hpp"
#include "details/iupdatekeystore.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SecurityLayer::SecurityLayer(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	, Details::IUpdateKeyStore &update_key_store
	, Details::ICertificateStore &certificate_store
	)
	: config_(config)
	, random_number_generator_(random_number_generator)
	, certificate_store_(certificate_store)
	, timeout_(io_context)
	, session_(io_context)
	, update_key_store_(update_key_store)
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
void SecurityLayer::onApplicationLayerTimeout() noexcept
{
    cancelPendingAPDU();
}
void SecurityLayer::cancelPendingAPDU() noexcept
{
	switch (state_)
	{
	case wait_for_session_start_request__ :
		reset();
		break;
	case wait_for_session_start_response__ :
	case wait_for_session_key_change_request__ :
	case wait_for_session_key_change_response__ :
	case normal_operation__ :
		discardAPDU();
		// no state change
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

std::pair< SecurityLayer::UpdateResult, boost::asio::steady_timer::duration> SecurityLayer::update() noexcept
{
    if (pollSPDU())
    {
        return make_pair(UpdateResult::spdu_ready__, boost::asio::steady_timer::duration(0));
    }
    else if (pollAPDU())
    {
        return make_pair(UpdateResult::apdu_ready__, boost::asio::steady_timer::duration(0));
    }
	if (getSession().valid(getOutgoingDirection()))
	{
		if (outgoing_apdu_.size())
		{
			onPostAPDU(outgoing_apdu_);
			return update();
		}
		else
		{ /* no APDU to handle */ }
    }
    else
	{ /* no valid session */ }
	if (getSession().valid(getOutgoingDirection()))
	{
		return make_pair(UpdateResult::wait__, min(timeout_.expires_from_now(), getSession().getTimeout().expires_from_now()));
	}
	else
	{
		return make_pair(UpdateResult::wait__, timeout_.expires_from_now());
	}
}

/*virtual */bool SecurityLayer::acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept
{
	return true;
}

/*virtual */bool SecurityLayer::acceptMACAlgorithm(AEADAlgorithm incoming_mal) const noexcept
{
	return true;
}

boost::asio::const_buffer SecurityLayer::getUpdateKey() const
{
	return update_key_store_.getUpdateKey(config_.master_outstation_association_name_);
}

void SecurityLayer::reset() noexcept
{
	discardAPDU();
	state_ = normal_operation__;
	incoming_apdu_ = const_buffer();
	incoming_spdu_ = const_buffer();
	outgoing_apdu_ = const_buffer();
	outgoing_spdu_ = const_buffer();
	seq_ = 0;
	seq_validator_.reset();
	//TODO make sure incoming authenticated APDUs don't affect this if we don't have a session 
	//TODO make sure this is reset if a new session is created (I think it already is)
	session_.reset();
	// don't touch statistics
	//TODO reset the timer
	
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
	clearPendingAPDU();
}

void SecurityLayer::queueAPDU(boost::asio::const_buffer const &apdu) noexcept
{
	memcpy(outgoing_apdu_buffer_, apdu.data(), apdu.size());
	outgoing_apdu_ = const_buffer(outgoing_apdu_buffer_, apdu.size());
}

void SecurityLayer::clearPendingAPDU() noexcept
{
	outgoing_apdu_ = const_buffer();
}

boost::asio::const_buffer SecurityLayer::formatSecureMessage(Details::Direction direction, boost::asio::const_buffer const &apdu) noexcept
{
    pre_condition(getSession().valid(direction));

    size_t const needed_space((10/*SPDU header size*/) + sizeof(Messages::SecureMessage) + apdu.size() + getAEADAlgorithmAuthenticationTagSize(session_.getAEADAlgorithm()));

    pre_condition(needed_space <= sizeof(outgoing_spdu_buffer_));

	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::secure_message__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

    const_buffer associated_data_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);

	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
    const_buffer nonce_buffer(outgoing_spdu_buffer_ + outgoing_spdu_size_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);

    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

    pre_condition(apdu.size() < numeric_limits< decltype(Messages::SecureMessage::apdu_length_) >::max());
    Messages::SecureMessage secure_message(static_cast< decltype(Messages::SecureMessage::apdu_length_) >(apdu.size()));
    unsigned char secure_message_serialized[sizeof(secure_message)];
    memcpy(secure_message_serialized, &secure_message, sizeof(secure_message));
    const_buffer secure_message_serialized_buffer(secure_message_serialized, sizeof(secure_message_serialized));

    mutable_buffer output_buffer(outgoing_spdu_buffer_ + outgoing_spdu_size_, needed_space - outgoing_spdu_size_);
    auto encrypt_result(
          encrypt(
              output_buffer
            , getSession().getAEADAlgorithm()
            , direction == Details::Direction::control__ ? getSession().getControlDirectionSessionKey() : getSession().getMonitoringDirectionSessionKey()
            , nonce_buffer
            , associated_data_buffer
            , secure_message_serialized_buffer
            , apdu
            )
        );
    outgoing_spdu_size_ += encrypt_result.size();

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

const_buffer SecurityLayer::format(Messages::AssociationInitiation const &message) noexcept
{
	return const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::AssociationRequest const &message, boost::asio::const_buffer const &encoded_certificates) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(message), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::association_request__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);
    
    static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	
    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &message, sizeof(message));
	outgoing_spdu_size_ += sizeof(message);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(message));

	if (sizeof(outgoing_spdu_buffer_) < outgoing_spdu_size_ + encoded_certificates.size())
	{
		//TODO log, stats
		return boost::asio::const_buffer();
	}
	else
	{ /* we have enough space to encode */ }
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, encoded_certificates.data(), encoded_certificates.size());
	outgoing_spdu_size_ += encoded_certificates.size();

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(uint32_t seq, Messages::AssociationResponse const& message, const_buffer const &certificates, const_buffer const &nonce) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(message), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::association_response__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);
    
    static_assert(sizeof(seq) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq, sizeof(seq));
	outgoing_spdu_size_ += sizeof(seq);
	
    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &message, sizeof(message));
	outgoing_spdu_size_ += sizeof(message);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(message));

	assert(outgoing_spdu_size_ + certificates.size() <= sizeof(outgoing_spdu_buffer_));
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, certificates.data(), certificates.size());
	outgoing_spdu_size_ += certificates.size();
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(message) + certificates.size());

	assert(outgoing_spdu_size_ + nonce.size() <= sizeof(outgoing_spdu_buffer_));
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, nonce.data(), nonce.size());
	outgoing_spdu_size_ += nonce.size();
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(message) + certificates.size() + nonce.size());

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::UpdateKeyChangeRequest const& message) noexcept
{
	return boost::asio::const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::UpdateKeyChangeResponse const& message) noexcept
{
	return boost::asio::const_buffer();
}

boost::asio::const_buffer SecurityLayer::format(Messages::SessionInitiation const &session_initiation) noexcept
{
    invariant(!getSession().valid(Details::Direction::monitoring__));

	static_assert(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_initiation__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

    static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);

    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::SessionStartRequest const &ssr) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(ssr), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_start_request__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);
    
    static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);
	
    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &ssr, sizeof(ssr));
	outgoing_spdu_size_ += sizeof(ssr);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(ssr));

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(std::uint32_t seq, Messages::SessionStartResponse const &ssr, const_buffer const &nonce) noexcept
{
	pre_condition(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(ssr) + nonce.size());
	
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_start_response__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

	static_assert(sizeof(seq) == sizeof(seq_), "wrong size (type) for seq");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq, sizeof(seq));
	outgoing_spdu_size_ += sizeof(seq);

	assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &ssr, sizeof(ssr));
	outgoing_spdu_size_ += sizeof(ssr);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(ssr));

	assert(ssr.challenge_data_length_ == nonce.size());
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, nonce.data(), nonce.size());
	outgoing_spdu_size_ += nonce.size();

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

const_buffer SecurityLayer::format(Messages::SessionKeyChangeRequest const &session_key_change_request, const_buffer const &wrapped_key_data) noexcept
{
	pre_condition(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(session_key_change_request) + wrapped_key_data.size());

	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_key_change_request__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

	static_assert(sizeof(seq_) == 4, "wrong size (type) for seq_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq_, sizeof(seq_));
	outgoing_spdu_size_ += sizeof(seq_);

	assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &session_key_change_request, sizeof(session_key_change_request));
	outgoing_spdu_size_ += sizeof(session_key_change_request);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(session_key_change_request));

	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, wrapped_key_data.data(), wrapped_key_data.size());
	outgoing_spdu_size_ += wrapped_key_data.size();
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(session_key_change_request) + wrapped_key_data.size());

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(std::uint32_t seq, Messages::SessionKeyChangeResponse const &session_key_change_response, boost::asio::const_buffer const &digest, unsigned int authentication_tag_length) noexcept
{
	pre_condition(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + /*sizeof(session_key_change_response) + */authentication_tag_length); // NOTE: in C++, the size of an empty struct is 1, so we don't want it in here. In C, it's 0 (as IMHO it should be)
    pre_condition(authentication_tag_length <= digest.size());
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_key_change_response__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

    static_assert(sizeof(seq) == sizeof(seq_), "wrong size (type) for seq");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq, sizeof(seq));
	outgoing_spdu_size_ += sizeof(seq);

	assert(outgoing_spdu_size_ == (10/*SPDU header size*/));

	// the SessionKeyChangeResponse structure is now empty, but as noted below, C++ gives this a size of 1, so we shouldn't copy it in
	//memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &session_key_change_response, sizeof(session_key_change_response));
	//outgoing_spdu_size_ += sizeof(session_key_change_response);
	//assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(session_key_change_response));

    memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, digest.data(), authentication_tag_length);
    outgoing_spdu_size_ += authentication_tag_length;

	return const_buffer(outgoing_spdu_buffer_, outgoing_spdu_size_);
}

boost::asio::const_buffer SecurityLayer::format(Messages::Error const &e) noexcept
{
	return format(seq_, e);
}

boost::asio::const_buffer SecurityLayer::format(std::uint32_t seq, Messages::Error const &e) noexcept
{
	static_assert(sizeof(outgoing_spdu_buffer_) >= (10/*SPDU header size*/) + sizeof(e), "buffer too small");
	outgoing_spdu_size_ = 0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0xC0;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x80;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = 0x40;
	outgoing_spdu_buffer_[outgoing_spdu_size_++] = static_cast< unsigned char >(Message::session_initiation__);

    static_assert(sizeof(config_.master_outstation_association_name_.association_id_) == 2, "wrong size (type) for association_id_");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &config_.master_outstation_association_name_.association_id_, sizeof(config_.master_outstation_association_name_.association_id_));
	outgoing_spdu_size_ += sizeof(config_.master_outstation_association_name_.association_id_);

	static_assert(sizeof(seq) == sizeof(seq_), "wrong size (type) for seq");
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &seq, sizeof(seq));
	outgoing_spdu_size_ += sizeof(seq);
	
    assert(outgoing_spdu_size_ == (10/*SPDU header size*/));
	
	memcpy(outgoing_spdu_buffer_ + outgoing_spdu_size_, &e, sizeof(e));
	outgoing_spdu_size_ += sizeof(e);
	assert(outgoing_spdu_size_ == (10/*SPDU header size*/) + sizeof(e));

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

/*virtual */void SecurityLayer::rxAssociationInitiation(std::uint32_t incoming_seq, boost::asio::const_buffer const &incoming_spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxAssociationRequest(std::uint32_t incoming_seq, Messages::AssociationRequest const &incoming_ar, boost::asio::const_buffer const &incoming_certificates, boost::asio::const_buffer const &incoming_spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxAssociationResponse(uint32_t incoming_seq, Messages::AssociationResponse const &incoming_ar, const_buffer const &incoming_outstation_certificate, const_buffer const &incoming_outstation_random_data, const_buffer const &incoming_spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxUpdateKeyChangeRequest(std::uint32_t incoming_seq, Messages::UpdateKeyChangeRequest const &incoming_ukcr, boost::asio::const_buffer const &incoming_spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxUpdateKeyChangeResponse(std::uint32_t incoming_seq, Messages::UpdateKeyChangeResponse const &incoming_ukcr, boost::asio::const_buffer const &incoming_spdu) noexcept
{
	incrementStatistic(Statistics::unexpected_messages__);
}
/*virtual */void SecurityLayer::rxSessionInitiation(uint32_t incoming_seq, boost::asio::const_buffer const &spdu) noexcept
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
/*virtual */void SecurityLayer::rxSessionKeyChangeRequest(uint32_t incoming_seq, Messages::SessionKeyChangeRequest const& incoming_skcr, boost::asio::const_buffer const& incoming_key_wrap_data, boost::asio::const_buffer const& spdu) noexcept
{
    incrementStatistic(Statistics::unexpected_messages__);
}

/*virtual */void SecurityLayer::rxSessionKeyChangeResponse(std::uint32_t incoming_seq, Messages::SessionKeyChangeResponse const &incoming_skcr, boost::asio::const_buffer const &incoming_mac, boost::asio::const_buffer const& spdu) noexcept
{
    incrementStatistic(Statistics::unexpected_messages__);
}

void SecurityLayer::rxSecureMessage(std::uint32_t incoming_seq, boost::asio::const_buffer const& incoming_nonce, boost::asio::const_buffer const& incoming_associated_data, boost::asio::const_buffer const& incoming_payload, boost::asio::const_buffer const& incoming_spdu) noexcept
{
    /* NOTE we don't check the state here: if we have a valid session, we use it.
     *      This means we can receive authenticated APDUs while a new session is being built.
     *      Whether the other side is actually capable of sending them in the current state
     *      is another matter. */
    if (!getSession().valid(getIncomingDirection()))
    {
		//TODO ask for session initiation
        incrementStatistic(Statistics::unexpected_messages__);
        return;
    }
    else
    { /* all is well */ }

    using Details::SEQValidator;
    switch (seq_validator_.validateSEQ(incoming_seq))
    {
    case SEQValidator::invalid_seq__ :
        incrementStatistic(Statistics::discarded_messages__);
        //TODO send an error in this case?
        return;
    case SEQValidator::old_seq__     :
        // either a replay attack or a network error. We shouldn't send an error message in either case
        //TODO log?
        incrementStatistic(Statistics::discarded_messages__); //TODO unexpected?
        return;
    case SEQValidator::repeat_seq__  :
        //TODO increment stats?
        return;
    case SEQValidator::next_seq__    :
    case SEQValidator::new_seq__     :
        break;
    }

    auto incoming_apdu(
          decrypt(
              mutable_buffer(incoming_apdu_buffer_, sizeof(incoming_apdu_buffer_))
            , getSession().getAEADAlgorithm()
            , getIncomingDirection() == Details::Direction::control__ ? getSession().getControlDirectionSessionKey() : getSession().getMonitoringDirectionSessionKey()
            , incoming_nonce
            , incoming_associated_data
            , incoming_payload
            )
        );

    if (!incoming_apdu.data()) // auth failure
    {   //TODO message if in maintenance mode
        //TODO statistics
        return;
    }
    else
    { /* all is well */ }

    assert(incoming_apdu.data() == incoming_apdu_buffer_);
    assert(incoming_apdu.size() <= sizeof(incoming_apdu_buffer_));

    unsigned char const *curr(static_cast< unsigned char const * >(incoming_apdu.data()));
    unsigned char const *const end(curr + incoming_apdu.size());

    Messages::SecureMessage incoming_sm;
    if (static_cast< size_t >(distance(curr, end)) < sizeof(incoming_sm)) // invalid message
    {   //TODO message if in maintenance mode
        //TODO statistics
        return;
    }
    else
    { /* all is well */ }
    memcpy(&incoming_sm, curr, sizeof(incoming_sm));
    curr += sizeof(incoming_sm);

    if (incoming_sm.apdu_length_ != distance(curr, end))
    { //TODO handle maintenance mode
        const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
        setOutgoingSPDU(response_spdu);
        incrementStatistic(Statistics::error_messages_sent__);
        incrementStatistic(Statistics::total_messages_sent__);
        return;
    }
    else
    { /* all is well */ }

    incoming_apdu_ = const_buffer(curr, incoming_sm.apdu_length_);
    seq_validator_.setLatestIncomingSEQ(incoming_seq);
}

void SecurityLayer::parseIncomingSPDU() noexcept
{
	unsigned char const *incoming_spdu_data(static_cast< unsigned char const* >(incoming_spdu_.data()));
	unsigned char const *curr(incoming_spdu_data);
	unsigned char const *const end(curr + incoming_spdu_.size());

    unsigned char const *const associated_data_begin(curr);
	if (distance(curr, end) < (10/*SPDU header size*/))
	{
		const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
		setOutgoingSPDU(response_spdu);
		incrementStatistic(Statistics::error_messages_sent__);
		incrementStatistic(Statistics::total_messages_sent__);
	}
	else
	{ /* it's at least big enough to be a valid SPDU */ }

	static const unsigned char preamble__[] = { 0xC0, 0x80, 0x40 };
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

    std::uint16_t incoming_association_id;
    static_assert(sizeof(incoming_association_id) == 2, "wrong size (type) for incoming_association_id");
    memcpy(&incoming_association_id, curr, sizeof(incoming_association_id));
    curr += 2;

	if ((incoming_association_id == 0) && (incoming_function_code != static_cast< uint8_t >(Message::association_request__)))
	{	// got a zero for a message where that is not allowed
		incrementStatistic(Statistics::wrong_association_id__);
        return;
	}
	else if ((incoming_association_id != 0) && (incoming_association_id != config_.master_outstation_association_name_.association_id_))
	{	// got non-zero and doesn't correspond to this stack's AID. May still be OK if the message is an association response
		if (incoming_function_code != static_cast< uint8_t >(Message::association_response__))
		{
			incrementStatistic(Statistics::wrong_association_id__);
			return;
		}
		else
		{ /* all is well */ }
	}

    unsigned char const *const associated_data_end(curr);

	decltype(seq_) incoming_seq;
	memcpy(&incoming_seq, curr, sizeof(incoming_seq));
    unsigned char const *nonce_begin(curr);
	curr += sizeof(incoming_seq);
    unsigned char const *nonce_end(curr);

	switch (incoming_function_code)
	{
	case static_cast< uint8_t >(Message::session_initiation__) :
		rxSessionInitiation(incoming_seq, incoming_spdu_);
		break;
	case static_cast< uint8_t >(Message::session_start_request__) :
		// check the SPDU size to see if it's big enough to hold a SessionStartRequest message
		// if so, parse into a SessionStartRequest object and call rxSessionStartRequest(incoming_seq, incoming_ssr);
		if (incoming_spdu_.size() == sizeof(Messages::SessionStartRequest) + (10/*header size*/))
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
		unsigned int const min_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionStartResponse) + Config::min_nonce_size__);
		unsigned int const max_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionStartResponse) + Config::max_nonce_size__);
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
	case static_cast< uint8_t >(Message::session_key_change_request__) :
    {
        // check the SPDU size to see if it's big enough to hold a SetSessionKeys message
        unsigned int const min_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionKeyChangeRequest));
        unsigned int const max_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionKeyChangeRequest) + Config::max_key_wrap_data_size__);
        if ((incoming_spdu_.size() >= min_expected_spdu_size) && (incoming_spdu_.size() <= max_expected_spdu_size))
        {
            Messages::SessionKeyChangeRequest incoming_skcr;
            assert(static_cast< size_t >(distance(curr, end)) >= sizeof(incoming_skcr));
            memcpy(&incoming_skcr, curr, sizeof(incoming_skcr));
            curr += sizeof(incoming_skcr);

            if (incoming_skcr.key_wrap_data_length_ == distance(curr, end))
            {
                const_buffer incoming_key_wrap_data(curr, distance(curr, end));
                rxSessionKeyChangeRequest(incoming_seq, incoming_skcr, incoming_key_wrap_data, incoming_spdu_);
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
        break;
    }
    case static_cast< uint8_t >(Message::session_key_change_response__) :
    {
        unsigned int const min_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionKeyChangeResponse));
        unsigned int const max_expected_spdu_size((10/*header size*/) + sizeof(Messages::SessionKeyChangeResponse) + Config::max_digest_size__);
        if ((incoming_spdu_.size() >= min_expected_spdu_size) && (incoming_spdu_.size() <= max_expected_spdu_size))
        {
            Messages::SessionKeyChangeResponse incoming_skcr;
			// Note: empty structs are 1 byte in C++, so skip this
            //assert(static_cast< size_t >(distance(curr, end)) > sizeof(incoming_skcr));
            //memcpy(&incoming_skcr, curr, sizeof(incoming_skcr));
            //curr += sizeof(incoming_skcr);

            const_buffer incoming_mac(curr, distance(curr, end));
            rxSessionKeyChangeResponse(incoming_seq, incoming_skcr, incoming_mac, incoming_spdu_);
        }
        else
        {
            const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
            setOutgoingSPDU(response_spdu);
            incrementStatistic(Statistics::error_messages_sent__);
            incrementStatistic(Statistics::total_messages_sent__);
        }
		break;
    }
	case static_cast< uint8_t >(Message::secure_message__) :
    {
        unsigned int const min_expected_spdu_size((10/*header size*/) + sizeof(Messages::SecureMessage) + 2/*minimal size of an APDU in either direction is two bytes, for the header with no objects*/ + getAEADAlgorithmAuthenticationTagSize(getSession().getAEADAlgorithm()));
        unsigned int const max_expected_spdu_size(Config::max_spdu_size__);
        if ((incoming_spdu_.size() >= min_expected_spdu_size) && (incoming_spdu_.size() <= max_expected_spdu_size))
        {
            const_buffer incoming_nonce(nonce_begin, distance(nonce_begin, nonce_end));
            const_buffer incoming_associated_data(associated_data_begin, distance(associated_data_begin, associated_data_end));
            const_buffer incoming_payload(curr, distance(curr, end));
            rxSecureMessage(incoming_seq, incoming_nonce, incoming_associated_data, incoming_payload, incoming_spdu_);
        }
        else
        {
            const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
            setOutgoingSPDU(response_spdu);
            incrementStatistic(Statistics::error_messages_sent__);
            incrementStatistic(Statistics::total_messages_sent__);
        }
		break;
    }
	case static_cast< uint8_t >(Message::association_initiation__) :
	{
		rxAssociationInitiation(incoming_seq, incoming_spdu_);
		break;
	}
	case static_cast< uint8_t >(Message::association_request__) :
	{
		// check the SPDU size to see if it's big enough to hold a SessionStartRequest message
		// if so, parse into a SessionStartRequest object and call rxSessionStartRequest(incoming_seq, incoming_ssr);
		if (incoming_spdu_.size() > sizeof(Messages::AssociationRequest) + (10/*header size*/))
		{
			Messages::AssociationRequest incoming_ar;
			incoming_ar.version_ = *curr++;
			if (incoming_ar.version_ != 6)
			{
				const_buffer response_spdu(format(Messages::Error(Messages::Error::unsupported_version__)));
				setOutgoingSPDU(response_spdu);
				incrementStatistic(Statistics::error_messages_sent__);
				incrementStatistic(Statistics::total_messages_sent__);
				break;
			}
			else
			{ /* all is well as far as the version is concerned */ }
 			incoming_ar.flags_ = *curr++;
			memcpy(&incoming_ar.master_certificate_length_, curr, sizeof(incoming_ar.master_certificate_length_));
			curr += sizeof(incoming_ar.master_certificate_length_);
			if (incoming_ar.master_certificate_length_ != distance(curr, end))
			{
				const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
				setOutgoingSPDU(response_spdu);
				incrementStatistic(Statistics::error_messages_sent__);
				incrementStatistic(Statistics::total_messages_sent__);
			}
			else
			{ /* length is OK */ }
			const_buffer incoming_certificates(curr, incoming_ar.master_certificate_length_);
			curr += incoming_ar.master_certificate_length_;
   			assert(curr == end);
			rxAssociationRequest(incoming_seq, incoming_ar, incoming_certificates, incoming_spdu_);
		}
		else
		{
			const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
		}
		break;
	}
	case static_cast< uint8_t >(Message::association_response__) :
	{
		// first, check that the incoming SPDU is at least large enough to hold the association response's non-variable parts
		if (incoming_spdu_.size() < sizeof(Messages::AssociationResponse) + (10 /* header size */))
		{
			const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		else
		{ /* OK so far */ }
		assert(distance(curr, end) >= sizeof(Messages::AssociationResponse));
		// read the non-variable parts
		Messages::AssociationResponse incoming_ar;
		static_assert(sizeof(incoming_ar) == 4, "Unexpected size for AssociationResponse type");
		memcpy(&incoming_ar, curr, sizeof(incoming_ar));
		curr += sizeof(incoming_ar);
		assert(curr < end);
		// check that the incoming SPDU is the expected size
		unsigned int const expected_total_size((10 /* header size */) + sizeof(incoming_ar) + incoming_ar.outstation_certificate_length_ + incoming_ar.outstation_random_data_length_);
		if (expected_total_size != incoming_spdu_.size())
		{
			const_buffer response_spdu(format(Messages::Error(Messages::Error::invalid_spdu__)));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		else
		{ /* OK so far */ }
		// carve out the certs and the random data
		const_buffer incoming_outstation_certificate(curr, incoming_ar.outstation_certificate_length_);
		curr += incoming_ar.outstation_certificate_length_;
		assert(curr < end);
		const_buffer incoming_outstation_random_data(curr, incoming_ar.outstation_random_data_length_);
		curr += incoming_ar.outstation_random_data_length_;
		assert(curr == end);
		// pass it all to the RX function
		rxAssociationResponse(incoming_seq, incoming_ar, incoming_outstation_certificate, incoming_outstation_random_data, incoming_spdu_);
		break;
	}
	case static_cast< uint8_t >(Message::update_key_change_request__) :
	{
		break;
	}
	case static_cast< uint8_t >(Message::update_key_change_response__) :
	{
		break;
	}
	case static_cast< uint8_t >(Message::error__) :
        //TODO
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


