/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "wrappedkeydata.hpp"
#include "../exceptions/contract.hpp"
#include "../details/rfc3394aes256keywrap.hpp"
#include "../config.hpp"

using namespace boost::asio;

namespace DNP3SAv6 { namespace Messages {
	namespace {
		template < KeyWrapAlgorithm kwa, AEADAlgorithm mal, typename KeyWrapAlgorithm >
        struct Wrapper
        {
            typedef typename WrappedKeyData< kwa, mal >::type WrappedKeyDataType;
		    static void wrap(
                  boost::asio::mutable_buffer &out
                , boost::asio::const_buffer const& key_encrypting_key
                , boost::asio::const_buffer const &control_direction_session_key
                , boost::asio::const_buffer const &monitoring_direction_session_key
                , boost::asio::const_buffer const &mac_value
                )
		    {
                KeyWrapAlgorithm key_wrap_algorithm;

			    pre_condition(control_direction_session_key.size() == sizeof(WrappedKeyDataType::control_direction_session_key_));
			    pre_condition(monitoring_direction_session_key.size() == sizeof(WrappedKeyDataType::monitoring_direction_session_key_));
			    pre_condition(mac_value.size() >= sizeof(WrappedKeyDataType::mac_value_));
			    pre_condition(out.size() >= KeyWrapAlgorithm::getWrappedDataSize(sizeof(WrappedKeyDataType)));

			    WrappedKeyDataType wrapped_data;
			    memcpy(wrapped_data.control_direction_session_key_, control_direction_session_key.data(), control_direction_session_key.size());
			    memcpy(wrapped_data.monitoring_direction_session_key_, monitoring_direction_session_key.data(), monitoring_direction_session_key.size());
			    memcpy(wrapped_data.mac_value_, mac_value.data(), sizeof(wrapped_data.mac_value_));
                out = mutable_buffer(out.data(), KeyWrapAlgorithm::getWrappedDataSize(sizeof(WrappedKeyDataType)));

			    const_buffer key_data(&wrapped_data, sizeof(wrapped_data));
			    key_wrap_algorithm.wrap(out, key_encrypting_key, key_data);
		    }
		    static bool unwrap(
                  boost::asio::mutable_buffer &control_direction_session_key
                , boost::asio::mutable_buffer &monitoring_direction_session_key
                , boost::asio::mutable_buffer &mac_value
                , boost::asio::const_buffer const &key_encrypting_key
                , boost::asio::const_buffer const &incoming_wrapped_key_data
                )
		    {
                KeyWrapAlgorithm key_wrap_algorithm;

                pre_condition(control_direction_session_key.size() >= sizeof(WrappedKeyDataType::control_direction_session_key_));
                pre_condition(monitoring_direction_session_key.size() >= sizeof(WrappedKeyDataType::monitoring_direction_session_key_));
                pre_condition(mac_value.size() >= sizeof(WrappedKeyDataType::mac_value_));

                if (sizeof(WrappedKeyDataType) != KeyWrapAlgorithm::getUnwrappedDataSize(incoming_wrapped_key_data.size()))
                {   //TODO statistics etc.
                    return false;
                }
                else
                { /* all is well so far */ }
                unsigned char buffer[sizeof(WrappedKeyDataType)];
                mutable_buffer out(buffer, sizeof(buffer));
			    if (key_wrap_algorithm.unwrap(out, key_encrypting_key, incoming_wrapped_key_data))
                {
                    post_condition(out.data() == buffer);
                    post_condition(out.size() == sizeof(buffer));

    			    WrappedKeyDataType *wrapped_data(reinterpret_cast< WrappedKeyDataType* >(buffer));
                    memcpy(control_direction_session_key.data(), wrapped_data->control_direction_session_key_, sizeof(wrapped_data->control_direction_session_key_));
                    control_direction_session_key = mutable_buffer(control_direction_session_key.data(), sizeof(wrapped_data->control_direction_session_key_));
                    memcpy(monitoring_direction_session_key.data(), wrapped_data->monitoring_direction_session_key_, sizeof(wrapped_data->monitoring_direction_session_key_));
                    monitoring_direction_session_key = mutable_buffer(monitoring_direction_session_key.data(), sizeof(wrapped_data->monitoring_direction_session_key_));
                    memcpy(mac_value.data(), wrapped_data->mac_value_, sizeof(wrapped_data->mac_value_));
                    mac_value = mutable_buffer(mac_value.data(), sizeof(wrapped_data->mac_value_));

                    return true;
                }
                else
                {   //TODO count appropriate statistic
                    return false;
                }
		    }
        };
	}
void wrap(
      boost::asio::mutable_buffer &out
    , boost::asio::const_buffer const& update_key
    , KeyWrapAlgorithm kwa
    , AEADAlgorithm mal
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
		case AEADAlgorithm::hmac_sha_256_truncated_8__		: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_8__,	    Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::hmac_sha_256_truncated_16__		: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_16__,     Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_8__	: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_8__,    Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::hmac_sha_3_256_truncated_16__	: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_16__,   Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::hmac_blake2s_truncated_8__		: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_8__,      Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::hmac_blake2s_truncated_16__		: Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_16__,     Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		case AEADAlgorithm::aes256_gcm__		            : Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::aes256_gcm__,                    Details::RFC3394AES256KeyWrap >::wrap(out, update_key, control_direction_session_key, monitoring_direction_session_key, mac_value); break;
		default :
			throw std::logic_error("Unknown MAC algorithm");
		}
		break;
	default :
		throw std::logic_error("Unknown key-wrap algorithm");
	}
}
bool unwrap(
      boost::asio::mutable_buffer &control_direction_session_key
    , boost::asio::mutable_buffer &monitoring_direction_session_key
    , boost::asio::mutable_buffer &mac_value
    , unsigned int &mac_value_size
    , boost::asio::const_buffer const& update_key
    , KeyWrapAlgorithm kwa
    , AEADAlgorithm mal
    , boost::asio::const_buffer const& incoming_wrapped_key_data
    )
{
	switch (kwa)
	{
	case KeyWrapAlgorithm::rfc3394_aes256_key_wrap__ :
		switch (mal)
		{
		case AEADAlgorithm::hmac_sha_256_truncated_8__		: mac_value_size =  8; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_8__,      Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		case AEADAlgorithm::hmac_sha_256_truncated_16__		: mac_value_size = 16; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_256_truncated_16__,     Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
        case AEADAlgorithm::hmac_sha_3_256_truncated_8__	: mac_value_size =  8; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_8__,    Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		case AEADAlgorithm::hmac_sha_3_256_truncated_16__	: mac_value_size = 16; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_sha_3_256_truncated_16__,   Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		case AEADAlgorithm::hmac_blake2s_truncated_8__		: mac_value_size =  8; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_8__,      Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		case AEADAlgorithm::hmac_blake2s_truncated_16__		: mac_value_size = 16; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::hmac_blake2s_truncated_16__,     Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		case AEADAlgorithm::aes256_gcm__		            : mac_value_size = 16; return Wrapper< KeyWrapAlgorithm::rfc3394_aes256_key_wrap__, AEADAlgorithm::aes256_gcm__,                    Details::RFC3394AES256KeyWrap >::unwrap(control_direction_session_key, monitoring_direction_session_key, mac_value, update_key, incoming_wrapped_key_data);
		default : 
			throw std::logic_error("Unknown MAC algorithm");
		}
        break;
	default :
		throw std::logic_error("Unknown key-wrap algorithm");
	}
}
}}

