#include "wrappedkeydata.hpp"
#include "exceptions/contract.hpp"
#include "details/rfc3394aes256keywrap.hpp"
#include "config.hpp"

using namespace boost::asio;

namespace DNP3SAv6 {
	namespace {
		template < typename W, typename A >
		void wrap_(A const &key_wrap_algorithm, boost::asio::mutable_buffer &out, boost::asio::const_buffer const& key_encrypting_key, boost::asio::const_buffer const &control_direction_session_key, boost::asio::const_buffer const &monitoring_direction_session_key, boost::asio::const_buffer const &mac_value)
		{
			pre_condition(control_direction_session_key.size() == sizeof(W::control_direction_session_key_));
			pre_condition(monitoring_direction_session_key.size() == sizeof(W::monitoring_direction_session_key_));
			pre_condition(mac_value.size() >= sizeof(W::mac_value_));
			pre_condition(out.size() >= A::getWrappedDataSize(sizeof(W)));

			W wrapped_data;
			memcpy(wrapped_data.control_direction_session_key_, control_direction_session_key.data(), control_direction_session_key.size());
			memcpy(wrapped_data.monitoring_direction_session_key_, monitoring_direction_session_key.data(), monitoring_direction_session_key.size());
			memcpy(wrapped_data.mac_value_, mac_value.data(), sizeof(wrapped_data.mac_value_));
            out = mutable_buffer(out.data(), A::getWrappedDataSize(sizeof(W)));

			const_buffer key_data(&wrapped_data, sizeof(wrapped_data));
			key_wrap_algorithm.wrap(out, key_encrypting_key, key_data);
		}
	}
void wrap(
      boost::asio::mutable_buffer &out
    , boost::asio::const_buffer const& update_key
    , KeyWrapAlgorithm kwa
    , MACAlgorithm mal
    , boost::asio::const_buffer const &control_direction_session_key
    , boost::asio::const_buffer const &monitoring_direction_session_key
    , boost::asio::const_buffer const &mac_value
    )
{
	switch (kwa)
	{
	case KeyWrapAlgorithm::rfc3394_aes256_key_wrap__ :
		switch (mal)
		{
		case MACAlgorithm::hmac_sha_256_truncated_8__		: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_8__		>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case MACAlgorithm::hmac_sha_256_truncated_16__		: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_256_truncated_16__		>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_8__		: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_8__	>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case MACAlgorithm::hmac_sha_3_256_truncated_16__	: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_sha_3_256_truncated_16__	>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case MACAlgorithm::hmac_blake2s_truncated_8__		: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_8__		>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case MACAlgorithm::hmac_blake2s_truncated_16__		: wrap_< WrappedKeyData< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, MACAlgorithm::hmac_blake2s_truncated_16__		>::type >(Details::RFC3394AES256KeyWrap(), out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		default :
			throw std::logic_error("Unknown MAC algorithm");
		}
		break;
	default :
		throw std::logic_error("Unknown key-wrap algorithm");
	}
}
}

