#include "catch.hpp"
#include "../outstation.hpp"

using namespace DNP3SAv6;

TEST_CASE( "Outstation: try to create an instance", "[outstation]" ) {
	boost::asio::io_context io_context;
	Config config;
	Outstation outstation(io_context, config);
}

//TODO add a test with an overloaded Outstation with accept* functions that may return false

