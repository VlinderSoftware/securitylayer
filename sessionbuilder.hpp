#ifndef dnp3sav6_sessionbuilder_hpp
#define dnp3sav6_sessionbuilder_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "config.hpp"
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"
#include "session.hpp"
#include <boost/asio.hpp>

namespace DNP3SAv6 {
namespace Details {
	class IRandomNumberGenerator;
}
class SessionBuilder
{
public :
	SessionBuilder(boost::asio::io_context &ioc, Details::IRandomNumberGenerator &random_number_generator);
	~SessionBuilder() = default;
	
	SessionBuilder(SessionBuilder &&other) noexcept = default;
	SessionBuilder& operator=(SessionBuilder &&other) noexcept = default;
	SessionBuilder(SessionBuilder const&) = delete;
	SessionBuilder& operator=(SessionBuilder const&) = delete;

	void reset() noexcept;

	void setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm);
	void setMACAlgorithm(MACAlgorithm mac_algorithm);

	// whole messages to calculate a MAC over
	void setSessionStartRequest(boost::asio::const_buffer const &spdu);
	void setSessionStartResponse(boost::asio::const_buffer const &spdu, boost::asio::const_buffer const &nonce);

	void setSessionKeyChangeInterval(std::chrono::seconds const &ttl_duration);
	void setSessionKeyChangeCount(unsigned int session_key_change_count);

	boost::asio::mutable_buffer createWrappedKeyData(boost::asio::mutable_buffer buffer);
    bool unwrapKeyData(boost::asio::const_buffer const& incoming_key_wrap_data);

    boost::asio::const_buffer getUpdateKey() const;

private :
	KeyWrapAlgorithm key_wrap_algorithm_ = KeyWrapAlgorithm::unknown__;
	MACAlgorithm mac_algorithm_ = MACAlgorithm::unknown__;

	unsigned char session_start_request_message_[Config::max_spdu_size__];
	unsigned int session_start_request_message_size_ = 0;
	unsigned char session_start_response_message_[Config::max_spdu_size__];
	unsigned int session_start_response_message_size_ = 0;
	unsigned char session_start_response_nonce_[Config::max_spdu_size__];
	unsigned int session_start_response_nonce_size_ = 0;

	boost::asio::steady_timer session_timeout_;
	unsigned int session_key_change_count_ = 0;

	Session session_;
	Details::IRandomNumberGenerator &random_number_generator_;
};
}

#endif
