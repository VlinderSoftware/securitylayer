#ifndef dnp3sav6_master_hpp
#define dnp3sav6_master_hpp

#include "securitylayer.hpp"

namespace DNP3SAv6 {
class Master : public SecurityLayer
{
public :
	Master(
		  boost::asio::io_context &io_context
		, Config config
		);
	~Master() = default;
	
	Master(Master &&other) noexcept = default;
	Master& operator=(Master &&other) noexcept = default;
	Master(Master const&) = delete;
	Master& operator=(Master const&) = delete;

protected :
	virtual void reset() noexcept override;
	virtual void onPostAPDU(boost::asio::const_buffer const &apdu) noexcept override;

private :
	void sendSessionStartRequest() noexcept;

	unsigned char buffer_[Config::max_spdu_size__];
};
}

#endif




