#include "catch.hpp"
#include "../outstation.hpp"
#include "../details/randomnumbergenerator.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace DNP3SAv6;

TEST_CASE( "Outstation: try to create an instance", "[outstation]" ) {
	boost::asio::io_context io_context;
	Config config;
	Details::RandomNumberGenerator rng;
	Outstation outstation(io_context, config, rng);
}

//TODO add a test with an overloaded Outstation with accept* functions that may return false

