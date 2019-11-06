#ifndef dnp3sav6_config_hpp
#define dnp3sav6_config_hpp

#include <cstdint>

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 {
	struct Config
	{
		unsigned int request_session_initiation_timeout_ = 5000; // milliseconds
		unsigned int session_start_request_timeout_ = 5000; // milliseconds
		unsigned int session_start_response_timeout_ = 5000; // milliseconds
		unsigned int set_session_keys_timeout_ = 5000; // milliseconds

		std::uint8_t key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
		std::uint8_t mac_algorithm_ = 4/* HMAC SHA256 T16*/;

		std::uint32_t session_key_change_interval_ = 60/*one hour*/;
		std::uint16_t session_key_change_count_ = 4096;

        //TODO check these in the session establishment
        std::uint32_t min_acceptable_session_key_change_interval_ = 10/*one hour*/;
		std::uint16_t min_acceptable_session_key_change_count_ = 1024;
		std::uint32_t max_acceptable_session_key_change_interval_ = 3600/*one hour*/;
		std::uint16_t max_acceptable_session_key_change_count_ = 65535;

		std::uint16_t nonce_size_ = 4; // bytes

        static unsigned int const max_key_wrap_data_size__ = 128; // some reasonable size for key-wrap data (it's currently 88 bytes). Note that a buffer for this is allocated on the stack, so we need this to be small

		static unsigned int const max_apdu_size__ = 4096;
		static unsigned int const max_spdu_size__ = 4096;
		static unsigned int const min_nonce_size__ = 4; // bytes
		static unsigned int const max_nonce_size__ = 16; // bytes

        static unsigned int const max_digest_size__ = 32; // bytes
        static unsigned int const max_session_key_size__ = 32; // bytes
	};
}

#endif

