#ifndef dnp3sav6_details_ikeywrap_hpp
#define dnp3sav6_details_ikeywrap_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details { 
class IKeyWrap
{
public :
	IKeyWrap() = default;
	virtual ~IKeyWrap() = default;

	IKeyWrap(IKeyWrap const&) = delete;
	IKeyWrap(IKeyWrap &&) = delete;
	IKeyWrap& operator=(IKeyWrap const&) = delete;
	IKeyWrap& operator=(IKeyWrap &&) = delete;

	virtual void wrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const = 0;
	virtual bool unwrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) const = 0;
};
}}

#endif
