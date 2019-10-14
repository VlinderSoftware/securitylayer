#ifndef dnp3sav6_master_hpp
#define dnp3sav6_master_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

#include "securitylayer.hpp"
#include "sessionbuilder.hpp"

namespace DNP3SAv6 {
class Master : public SecurityLayer
{
public :
	Master(
		  boost::asio::io_context &io_context
		, Config config
		, Details::IRandomNumberGenerator &random_number_generator
		);
	virtual ~Master() = default;
	
	Master(Master &&other) noexcept = default;
	Master& operator=(Master &&other) noexcept = default;
	Master(Master const&) = delete;
	Master& operator=(Master const&) = delete;

protected :
	virtual void reset() noexcept override;
	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept override;

	virtual void rxRequestSessionInitiation(uint32_t incoming_seq, boost::asio::const_buffer const &spdu) noexcept override;
	virtual void rxSessionStartResponse(uint32_t incoming_seq, Messages::SessionStartResponse const &incoming_ssr, boost::asio::const_buffer const &nonce, boost::asio::const_buffer const &spdu) noexcept override;
    virtual void rxSessionConfirmation(std::uint32_t incoming_seq, Messages::SessionConfirmation const &incoming_sc, boost::asio::const_buffer const &incoming_mac, boost::asio::const_buffer const& spdu) noexcept override;

private :
	void sendSessionStartRequest() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
#if OPTION_ITERATE_KWA_AND_MAL
	unsigned int kwa_index_;
	unsigned int mal_index_;
#endif
	SessionBuilder session_builder_;
};
}

#endif




