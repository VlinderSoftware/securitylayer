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

protected :
	/* Library hooks.
	 * NOTE: the incoming stuff is not authenticated yet. DO NOT take any descisions based on this incoming data. Only 
	 *       tell the implementation if you'd be willing, according to your configuration, to accept the proposed 
	 *       key-wrap algorithm and MAC algorithm. DO NOT presume that these will actually be used for anything, so
	 *       don't start allocating resources etc. Also don't log everything: that can be used as DOS attacks on your
	 *       logs. The fewer side-effects the better. */
	virtual bool acceptKeyWrapAlgorithm(KeyWrapAlgorithm incoming_kwa) const noexcept;
	virtual bool acceptMACAlgorithm(MACAlgorithm incoming_mal) const noexcept;

private :
	void sendRequestSessionInitiation() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
	unsigned char nonce_[Config::max_nonce_size__];
	SessionBuilder session_builder_;
};
}

#endif



