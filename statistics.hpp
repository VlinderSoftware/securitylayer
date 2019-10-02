#ifndef dnp3sav6_statistics_hpp
#define dnp3sav6_statistics_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

namespace DNP3SAv6 {
	enum struct Statistics : int {
		  total_messages_sent__ = 0
		, total_messages_received__
		, discarded_messages__
		, error_messages_sent__
		, unexpected_messages__
		, authenticated_apdus_sent__

		// INSERT NEW ONES ABOVE
		, statistics_count__
		};
}

#endif




