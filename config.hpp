#ifndef dnp3sav6_config_hpp
#define dnp3sav6_config_hpp

namespace DNP3SAv6 {
	struct Config
	{
		unsigned int request_session_initiation_timeout_ = 5000; // milliseconds
		unsigned int session_start_request_timeout_ = 5000; // milliseconds

		static unsigned int const max_apdu_size__ = 4096;
		static unsigned int const max_spdu_size__ = 4096;
	};
}

#endif

