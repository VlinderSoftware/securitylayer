#include "sessionbuilder.hpp"
#include "exceptions/contract.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SessionBuilder::SessionBuilder(boost::asio::io_context &ioc)
	: session_timeout_(ioc)
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

void SessionBuilder::sessionKeyChangeCount(unsigned int session_key_change_count)
{
	session_key_change_count_ = session_key_change_count;
}

mutable_buffer SessionBuilder::createWrappedKeyData(mutable_buffer buffer) const
{
	unsigned char *curr(static_cast< unsigned char* >(buffer.data()));
	unsigned char *const end(curr + buffer.size());

}

}




