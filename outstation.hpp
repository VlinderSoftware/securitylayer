#ifndef dnp3sav6_outstation_hpp
#define dnp3sav6_outstation_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "securitylayer.hpp"
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"
#include "sessionbuilder.hpp"

namespace DNP3SAv6 {
class Outstation : public SecurityLayer
{
public :
	Outstation(
		  boost::asio::io_context &io_context
		, Config config
		, Details::IRandomNumberGenerator &random_number_generator
		);
	virtual ~Outstation() = default;
	
	Outstation(Outstation &&other) noexcept = default;
	Outstation& operator=(Outstation &&other) noexcept = default;
	Outstation(Outstation const&) = delete;
	Outstation& operator=(Outstation const&) = delete;

protected :
	virtual void reset() noexcept override;
	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept override;

	virtual void rxSessionStartRequest(std::uint32_t incoming_seq, Messages::SessionStartRequest const &incoming_ssr, boost::asio::const_buffer const &spdu) noexcept override;

private :
	void sendRequestSessionInitiation() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
	unsigned char nonce_[Config::max_nonce_size__];
	SessionBuilder session_builder_;
};
}

#endif



