#ifndef dnp3sav6_details_ihmac_hpp
#define dnp3sav6_details_ihmac_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details { 
	class IHMAC
	{
	public :
		IHMAC() = default;
		virtual ~IHMAC() = default;

		IHMAC(IHMAC const&) = delete;
		IHMAC(IHMAC &&) = default;
		IHMAC& operator=(IHMAC const&) = delete;
		IHMAC& operator=(IHMAC &&) = default;

		virtual void setKey(boost::asio::const_buffer const &key) = 0;
		virtual void digest(boost::asio::const_buffer const &data) = 0;
		virtual boost::asio::const_buffer get() = 0;
		virtual bool verify(boost::asio::const_buffer const &digest) = 0;
	};
}}

#endif
