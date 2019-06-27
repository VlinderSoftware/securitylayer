#ifndef dnp3sav6_sessionbuilder_hpp
#define dnp3sav6_sessionbuilder_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include <boost/asio.hpp>
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"

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

	void setKeyWrapAlgorithm(KeyWrapAlgorithm key_wrap_algorithm);
	void setMACAlgorithm(MACAlgorithm mac_algorithm);

	// whole messages to calculate a MAC over
	void setSessionStartRequest(boost::asio::const_buffer const &spdu);
	void setSessionStartResponse(boost::asio::const_buffer const &spdu, boost::asio::const_buffer const &nonce);
};
}

#endif
