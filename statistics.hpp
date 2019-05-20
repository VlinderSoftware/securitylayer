#ifndef dnp3sav6_statistics_hpp
#define dnp3sav6_statistics_hpp

namespace DNP3SAv6 {
	enum struct Statistics : int {
		  total_messages_sent__ = 0
		, total_messages_received__
		, discarded_messages__
		, error_messages_sent__
		, unexpected_messages__

		// INSERT NEW ONES ABOVE
		, statistics_count__
		};
}

#endif




