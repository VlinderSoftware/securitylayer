#ifndef dnp3sav6_config_hpp
#define dnp3sav6_config_hpp

namespace DNP3SAv6 {
	struct Config
	{
		unsigned int request_session_initiation_timeout_ = 5000; // milliseconds
		unsigned int session_start_request_timeout_ = 5000; // milliseconds
		unsigned int session_start_response_timeout_ = 5000; // milliseconds

		std::uint8_t key_wrap_algorithm_ = 2/*NIST SP800-38F AES-256 GCM*/;
		std::uint8_t mac_algorithm_ = 4/* HMAC SHA256 T16*/;
		std::uint32_t session_key_change_interval_ = 60/*one hour*/;
		std::uint16_t session_key_change_count_ = 4096;
		std::uint16_t nonce_size_ = 4;

		static unsigned int const max_apdu_size__ = 4096;
		static unsigned int const max_spdu_size__ = 4096;
		static unsigned int const max_nonce_size__ = 16; // bytes
	};
}

#endif

