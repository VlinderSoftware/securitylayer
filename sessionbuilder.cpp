#include "sessionbuilder.hpp"
#include "exceptions/contract.hpp"
#include "details/irandomnumbergenerator.hpp"
#include "hmac.hpp"
#include "wrappedkeydata.hpp"

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
	session_start_request_message_size_ = 0;
	session_start_response_message_size_ = 0;
	session_start_response_nonce_size_ = 0;
	session_key_change_count_ = 0;
}

void SessionBuilder::setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm)
{
	key_wrap_algorithm_ = key_wrap_algorithm;
}

void SessionBuilder::setMACAlgorithm(MACAlgorithm mac_algorithm)
{
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
	unsigned char *curr(static_cast< unsigned char* >(buffer.data()));
	unsigned char *const end(curr + buffer.size());

	random_number_generator_.generate(mutable_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_)));
	random_number_generator_.generate(mutable_buffer(session_.monitoring_direction_session_key_, sizeof(session_.monitoring_direction_session_key_)));
	// calculate the MAC over the first two messages using the control direction session key
	unsigned char digest_value[32];
	digest(mutable_buffer(digest_value, sizeof(digest_value)), mac_algorithm_, const_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_)), const_buffer(session_start_request_message_, session_start_request_message_size_), const_buffer(session_start_response_message_, session_start_response_message_size_));
	// encode it all into the mutable buffer
	wrap(
		  buffer
		, key_wrap_algorithm_
		, mac_algorithm_
		, const_buffer(session_.control_direction_session_key_, sizeof(session_.control_direction_session_key_))
		, const_buffer(session_.monitoring_direction_session_key_, sizeof(session_.monitoring_direction_session_key_))
		, const_buffer(digest_value, sizeof(digest_value))
		);

	return buffer;
}

}




