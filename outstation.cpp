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
#include "outstation.hpp"
#include "messages.hpp"
#include "details/irandomnumbergenerator.hpp"
#include "exceptions/contract.hpp"
#include "messages.hpp"
#include "details/icertificatestore.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
Outstation::Outstation(
	  boost::asio::io_context &io_context
	, Config config
	, Details::IRandomNumberGenerator &random_number_generator
	, Details::IUpdateKeyStore &update_key_store
	, Details::ICertificateStore &certificate_store
	)
	: SecurityLayer(io_context, config, random_number_generator, update_key_store, certificate_store)
	, session_builder_(io_context, random_number_generator, update_key_store, config)
{ /* no-op */ }

/*virtual */void Outstation::reset() noexcept/* override*/
{
	SecurityLayer::reset();
}
/*virtual */void Outstation::onPostAPDU(boost::asio::const_buffer const &apdu) noexcept/* override*/
{
    /* NOTE we don't check the state here: if we have a valid session, we use it.
     *      This means we can send secure messages while a new session is being built. 
     *      The Master may or may not accept those messages, according to its own state, but 
     *      we don't care at this point. If it doesn't accept the APDUs, they'll just time 
     *      out. */
    if (getSession().valid(Details::Direction::monitoring__))
    {
		incrementSEQ();
        setOutgoingSPDU(formatSecureMessage(Details::Direction::monitoring__, apdu), std::chrono::seconds(config_.session_key_change_interval_));
        incrementStatistic(Statistics::secure_messages_sent_);
        incrementStatistic(Statistics::total_messages_sent__);
		clearPendingAPDU();
    }
    else
    {
		switch (getState())
	    {
	    case normal_operation__ :
		    incrementSEQ();
	    case wait_for_session_start_request__ :
		    sendSessionInitiation();
		    setState(wait_for_session_start_request__);
		    break;
	    case wait_for_session_key_change_request__ :
		    /* no-op: sending SessionStartResponse is drive by its time-out or receiving 
		     * SessionStartRequest messages, not by APDUs */
		    break;
		case wait_for_association_request__ :
			//TODO
		case wait_for_update_key_change_request__ :
			//TODO
	    default :
		    assert(!"unexpected state");
	    }
    }
}

/*virtual */void Outstation::rxSessionStartRequest(uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &incoming_spdu) noexcept/* override*/
{
	Messages::SessionStartResponse response;

	const_buffer response_spdu;
	switch (getState())
	{
	case normal_operation__ :
		session_builder_.reset();
	case wait_for_session_start_request__ :
	{
        session_builder_.setSEQ(incoming_seq);
		// check the values in the session start request to see if I can live with them
		if (incoming_ssr.version_ == 6)
		{ /* OK so far */ }
		else
		{
			response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unsupported_version__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		if (incoming_ssr.flags_ == 0)
		{ /* still OK */ }
		else
		{
			response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unexpected_flags__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		session_builder_.setSessionStartRequest(incoming_spdu);

		assert(config_.session_handshake_nonce_size_ <= config_.max_nonce_size__);
		boost::asio::mutable_buffer nonce_buffer(nonce_, config_.session_handshake_nonce_size_);
		random_number_generator_.generate(nonce_buffer);
		response.challenge_data_length_ = config_.session_handshake_nonce_size_;

		response_spdu = format(session_builder_.getSEQ(), response, nonce_buffer);
		
		session_builder_.setSessionStartResponse(response_spdu, nonce_buffer);
		setState(State::wait_for_session_key_change_request__);
		setOutgoingSPDU(response_spdu, std::chrono::milliseconds(config_.session_start_response_timeout_));
		incrementStatistic(Statistics::total_messages_sent__);
		return;
	}
	case wait_for_session_key_change_request__ :
		//TODO if the sequence number is the same, re-send our response -- make sure to use the same nonce
		//     if the sequence number is one higher, and values for the KWA and the MAL from the Master are hints, treat them 
		//     otherwise increment appropriate statistics and ignore
	case wait_for_association_request__ :
		//TODO
	case wait_for_update_key_change_request__ :
		//TODO
	default :
		assert(!"unexpected state");
	}
//session_key_change_interval_ = 60/*one hour*/;
//session_key_change_count_ = 4096;
//send the response_spdu HERE!!
}

/*virtual */void Outstation::rxSessionKeyChangeRequest(
      uint32_t incoming_seq
    , Messages::SessionKeyChangeRequest const& incoming_skcr
    , boost::asio::const_buffer const& incoming_key_wrap_data
    , boost::asio::const_buffer const& spdu
    ) noexcept/* override*/
{
    pre_condition(incoming_skcr.key_wrap_data_length_ == incoming_key_wrap_data.size());

    const_buffer response_spdu;
    switch (getState())
    {
    case normal_operation__:
        // fall through
    case wait_for_session_start_request__:
        response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unexpected_spdu__));
        setOutgoingSPDU(response_spdu);
        incrementStatistic(Statistics::error_messages_sent__);
        incrementStatistic(Statistics::total_messages_sent__);
        return;
    case wait_for_session_key_change_request__:
    {
		if (acceptKeyWrapAlgorithm(static_cast< KeyWrapAlgorithm >(incoming_skcr.key_wrap_algorithm_)))
		{
            session_builder_.setKeyWrapAlgorithm(static_cast<KeyWrapAlgorithm>(incoming_skcr.key_wrap_algorithm_));
        }
		else
		{
			response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unsupported_keywrap_algorithm__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			return;
		}
		if (acceptMACAlgorithm(static_cast< AEADAlgorithm >(incoming_skcr.aead_algorithm_)))
		{
            session_builder_.setMACAlgorithm(static_cast< AEADAlgorithm >(incoming_skcr.aead_algorithm_));
        }
		else
		{
			response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unsupported_mac_algorithm__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			return;
		}
        session_builder_.setSessionKeyChangeRequest(const_buffer(&incoming_skcr, sizeof(incoming_skcr)));
        // try to unwrap the wrapped key data
        if (session_builder_.unwrapKeyData(incoming_key_wrap_data))
        {
            response_spdu = format(
				  session_builder_.getSEQ()
				, Messages::SessionKeyChangeResponse()
				, session_builder_.getDigest(Details::Direction::monitoring__)
				, getAEADAlgorithmAuthenticationTagSize(session_builder_.getAEADAlgorithm())
				);
            setOutgoingSPDU(response_spdu, std::chrono::seconds(config_.session_key_change_interval_));
            incrementStatistic(Statistics::total_messages_sent__);
            if (getSession().valid(Details::Direction::monitoring__))
            { //TODO if we set up a second (replacement) session, we won't use it until the Master has sent us an authenticated APDU using it, or the old one times out
            }
            else
            {
				auto session(session_builder_.getSession());
                setSession(session);
                setSEQ(0);
                seq_validator_.reset();
            }
            setState(State::normal_operation__);
        }
        else
        {
            // only send detailed error message in maintenance mode. Don't send any message if we're not.
            response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::authentication_failure__));
            setOutgoingSPDU(response_spdu);
            incrementStatistic(Statistics::error_messages_sent__);
            incrementStatistic(Statistics::total_messages_sent__);
        }
        return;
    }
	case wait_for_association_request__ :
		//TODO
	case wait_for_update_key_change_request__ :
		//TODO
    default:
        assert(!"unexpected state");
    }
    //session_key_change_interval_ = 60/*one hour*/;
    //session_key_change_count_ = 4096;
    //send the response_spdu HERE!!
}

/*virtual */void Outstation::rxAssociationRequest(std::uint32_t incoming_seq, Messages::AssociationRequest const &incoming_ar, boost::asio::const_buffer const &incoming_spdu) noexcept/* override*/
{
    const_buffer response_spdu;
	Messages::AssociationResponse response;

	switch (getState())
	{
	case normal_operation__ :
	case wait_for_association_request__ :
	{
        association_builder_.setSEQ(incoming_seq);
		// check the values in the session start request to see if I can live with them
		if (incoming_ar.version_ == 6)
		{ /* OK so far */ }
		else
		{
			response_spdu = format(association_builder_.getSEQ(), Messages::Error(Messages::Error::unsupported_version__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		if (incoming_ar.flags_ == 0)
		{ /* still OK */ }
		else
		{
			response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unexpected_flags__));
			setOutgoingSPDU(response_spdu);
			incrementStatistic(Statistics::error_messages_sent__);
			incrementStatistic(Statistics::total_messages_sent__);
			break;
		}
		association_builder_.setAssociationRequest(incoming_spdu);

		assert(config_.association_handshake_nonce_size_ <= config_.max_nonce_size__);
		boost::asio::mutable_buffer nonce_buffer(nonce_, config_.association_handshake_nonce_size_);
		random_number_generator_.generate(nonce_buffer);
		response.outstation_random_data_length_ = config_.association_handshake_nonce_size_;
		auto certificates(certificate_store_.encode(config_.certificate_name_, config_.include_certificate_chain_));
		if (certificates.empty())
		{
#if !defined(OPTION_PERMIT_NO_CERTIFICATE_IN_ASSOCIATION_RESPONSE) || !OPTION_PERMIT_NO_CERTIFICATE_IN_ASSOCIATION_RESPONSE
			//TODO log
			return;
#endif
		}
		else
		{ /* all is well */ }
		const_buffer certificates_buffer(certificates.empty() ? nullptr : &certificates[0], certificates.size());
		if (certificates_buffer.size() > std::numeric_limits< decltype(response.outstation_certificate_length_) >::max())
		{
			//TODO log
			return;
		}
		else
		{ /* all is well */ }
		response.outstation_certificate_length_ = certificates_buffer.size();
		response_spdu = format(association_builder_.getSEQ(), response, certificates_buffer, nonce_buffer);
		
		association_builder_.setAssociationResponse(response_spdu);
		setState(State::wait_for_session_key_change_request__);
		setOutgoingSPDU(response_spdu, std::chrono::milliseconds(config_.session_start_response_timeout_));
		incrementStatistic(Statistics::total_messages_sent__);
		return;
	}
	case wait_for_update_key_change_request__ :
		//TODO re-send the association response
		break;
	case wait_for_session_start_request__ :
	case wait_for_session_key_change_request__ :
        response_spdu = format(session_builder_.getSEQ(), Messages::Error(Messages::Error::unexpected_spdu__));
        setOutgoingSPDU(response_spdu);
        incrementStatistic(Statistics::error_messages_sent__);
        incrementStatistic(Statistics::total_messages_sent__);
        break;
	default :
        assert(!"unexpected state");
	}
}

void Outstation::sendSessionInitiation() noexcept
{
	const_buffer spdu(format(Messages::SessionInitiation()));
	setOutgoingSPDU(spdu, std::chrono::milliseconds(config_.request_session_initiation_timeout_));
	incrementStatistic(Statistics::total_messages_sent__);
}
}




