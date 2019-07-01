#ifndef dnp3sav6_details_rfc3394aes256keywrap_hpp
#define dnp3sav6_details_rfc3394aes256keywrap_hpp

#include "ikeywrap.hpp" 

namespace DNP3SAv6 { namespace Details {
class RFC3394AES256KeyWrap : public IKeyWrap
{
public:
	RFC3394AES256KeyWrap();
	virtual ~RFC3394AES256KeyWrap();

	RFC3394AES256KeyWrap(RFC3394AES256KeyWrap const&) = delete;
	RFC3394AES256KeyWrap(RFC3394AES256KeyWrap &&) = delete;
	RFC3394AES256KeyWrap& operator=(RFC3394AES256KeyWrap const&) = delete;
	RFC3394AES256KeyWrap& operator=(RFC3394AES256KeyWrap &&) = delete;

	virtual void wrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) override;
	virtual bool unwrap(boost::asio::mutable_buffer &out, boost::asio::const_buffer const &key_encrypting_key, boost::asio::const_buffer const &key_data) override;

private :
	static unsigned char const default_iv__[8];
};
}}

#endif
