#include "sessionbuilder.hpp"
#include "exceptions/contract.hpp"
#include "details/irandomnumbergenerator.hpp"
#include "hmac.hpp"
#include "wrappedkeydata.hpp"
#include <openssl/crypto.h>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SessionBuilder::SessionBuilder(boost::asio::io_context &ioc, Details::IRandomNumberGenerator &random_number_generator)
	: session_timeout_(ioc)
	, random_number_generator_(random_number_generator)
{
}

void SessionBuilder::reset() noexcept
{
    key_wrap_algorithm_ = KeyWrapAlgorithm::unknown__;
    mac_algorithm_ = MACAlgorithm::unknown__;
	session_start_request_message_size_ = 0;
	session_start_response_message_size_ = 0;
	session_start_response_nonce_size_ = 0;
	session_key_change_count_ = 0;
}

void SessionBuilder::setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm)
{
    pre_condition(key_wrap_algorithm != KeyWrapAlgorithm::unknown__);
	key_wrap_algorithm_ = key_wrap_algorithm;
}

void SessionBuilder::setMACAlgorithm(MACAlgorithm mac_algorithm)
{
    pre_condition(mac_algorithm != MACAlgorithm::unknown__);
	mac_algorithm_ = mac_algorithm;
}

void SessionBuilder::setSessionStartRequest(const_buffer const &spdu)
{
	pre_condition(spdu.size() <= sizeof(session_start_request_message_));
	memcpy(session_start_request_message_, spdu.data(), spdu.size());
	session_start_request_message_size_ = spdu.size();
}
void SessionBuilder::setSessionStartResponse(const_buffer const &spdu, const_buffer const &nonce)
{
	pre_condition(spdu.size() <= sizeof(session_start_request_message_));
	pre_condition(nonce.size() <= sizeof(session_start_response_nonce_));
	memcpy(session_start_response_message_, spdu.data(), spdu.size());
	session_start_response_message_size_ = spdu.size();
	memcpy(session_start_response_nonce_, nonce.data(), nonce.size());
	session_start_response_nonce_size_ = nonce.size();
}

void SessionBuilder::setSessionKeyChangeInterval(std::chrono::seconds const &ttl_duration)
{
	session_timeout_.expires_after(ttl_duration);
}

void SessionBuilder::setSessionKeyChangeCount(unsigned int session_key_change_count)
{
	session_key_change_count_ = session_key_change_count;
}

mutable_buffer SessionBuilder::createWrappedKeyData(mutable_buffer buffer)
{
    pre_condition(key_wrap_algorithm_ != KeyWrapAlgorithm::unknown__);
    pre_condition(mac_algorithm_ != MACAlgorithm::unknown__);

	unsigned char *curr(static_cast< unsigned char* >(buffer.data()));
	unsigned char *const end(curr + buffer.size());

	random_number_generator_.generate(mutable_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_)));
	random_number_generator_.generate(mutable_buffer(session_.monitoring_direction_session_key_, sizeof(session_.monitoring_direction_session_key_)));
	// calculate the MAC over the first two messages using the control direction session key
	unsigned char digest_value[Config::max_digest_size__];
	digest(mutable_buffer(digest_value, sizeof(digest_value)), mac_algorithm_, const_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_)), const_buffer(session_start_request_message_, session_start_request_message_size_), const_buffer(session_start_response_message_, session_start_response_message_size_));
	// encode it all into the mutable buffer
	wrap(
		  buffer
        , getUpdateKey()
		, key_wrap_algorithm_
		, mac_algorithm_
		, const_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_))
		, const_buffer(session_.monitoring_direction_session_key_, sizeof(session_.monitoring_direction_session_key_))
		, const_buffer(digest_value, sizeof(digest_value))
		);

	return buffer;
}

bool SessionBuilder::unwrapKeyData(boost::asio::const_buffer const& incoming_key_wrap_data)
{
    pre_condition(key_wrap_algorithm_ != KeyWrapAlgorithm::unknown__);
    pre_condition(mac_algorithm_ != MACAlgorithm::unknown__);

    pre_condition(incoming_key_wrap_data.size() <= Config::max_key_wrap_data_size__);

    // calculate the MAC over the first two messages using the control direction session key
    unsigned char incoming_control_direction_session_key[sizeof(session_.control_direction_session_key_)];
    unsigned char incoming_monitoring_direction_session_key[sizeof(session_.monitoring_direction_session_key_)];
    unsigned char incoming_digest_value[Config::max_digest_size__];
    unsigned int incoming_digest_value_size(0);

    if (unwrap(
          mutable_buffer(incoming_control_direction_session_key, sizeof(incoming_control_direction_session_key))
        , mutable_buffer(incoming_monitoring_direction_session_key, sizeof(incoming_monitoring_direction_session_key))
        , mutable_buffer(incoming_digest_value, sizeof(incoming_digest_value))
        , incoming_digest_value_size
        , getUpdateKey()
        , key_wrap_algorithm_
        , mac_algorithm_
        , incoming_key_wrap_data
        ))
    {
        // the incoming digest value size is determined by the algorithm used, so we don't need to check it at run-time (though we assert to make sure our buffer is big enough here)
        assert(incoming_digest_value_size <= sizeof(incoming_digest_value));

        unsigned char expected_digest_value[Config::max_digest_size__];
        digest(mutable_buffer(expected_digest_value, sizeof(expected_digest_value)), mac_algorithm_, const_buffer(incoming_control_direction_session_key, sizeof(incoming_control_direction_session_key)), const_buffer(session_start_request_message_, session_start_request_message_size_), const_buffer(session_start_response_message_, session_start_response_message_size_));

        if (CRYPTO_memcmp(expected_digest_value, incoming_digest_value, incoming_digest_value_size) == 0)
        {
            static_assert(sizeof(session_.control_direction_session_key_) == sizeof(incoming_control_direction_session_key), "unexpected size mismatch");
            memcpy(session_.control_direction_session_key_, incoming_control_direction_session_key, sizeof(incoming_control_direction_session_key));
            static_assert(sizeof(session_.monitoring_direction_session_key_) == sizeof(incoming_monitoring_direction_session_key), "unexpected size mismatch");
            memcpy(session_.monitoring_direction_session_key_, incoming_monitoring_direction_session_key, sizeof(incoming_monitoring_direction_session_key));
            memcpy(digest_, expected_digest_value, Config::max_digest_size__);
            return true;
        }
        else
        { //TODO stats and somesuch
        }
    }
    else
    { //TODO stats and somesuch
    }

    return false;
}

boost::asio::const_buffer SessionBuilder::getUpdateKey() const
{   //TODO get this from somewhere
    static unsigned char const update_key__[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        , 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
    return const_buffer(update_key__, sizeof(update_key__));
}

KeyWrapAlgorithm SessionBuilder::getKeyWrapAlgorithm() const
{
    return key_wrap_algorithm_;
}

MACAlgorithm SessionBuilder::getMACAlgorithm() const
{
    return mac_algorithm_;
}

boost::asio::const_buffer SessionBuilder::getDigest() const
{
    return boost::asio::const_buffer(digest_, sizeof(digest_));
}


}




