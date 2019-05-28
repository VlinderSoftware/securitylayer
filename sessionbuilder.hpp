#ifndef dnp3sav6_sessionbuilder_hpp
#define dnp3sav6_sessionbuilder_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 {
class SessionBuilder
{
public :
	SessionBuilder();
	~SessionBuilder() = default;
	
	SessionBuilder(SessionBuilder &&other) noexcept = default;
	SessionBuilder& operator=(SessionBuilder &&other) noexcept = default;
	SessionBuilder(SessionBuilder const&) = delete;
	SessionBuilder& operator=(SessionBuilder const&) = delete;

	void reset() noexcept;

	void setSessionStartRequest(boost::asio::const_buffer const &spdu);
	void setSessionStartResponse(boost::asio::const_buffer const &spdu, boost::asio::const_buffer const &nonce);
};
}

#endif
