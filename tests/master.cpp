#include "catch.hpp"
#include "../master.hpp"
#include "../details/randomnumbergenerator.hpp"

using namespace DNP3SAv6;

TEST_CASE( "Master: try to create an instance", "[master]" ) {
	boost::asio::io_context io_context;
	Config config;
	Details::RandomNumberGenerator rng;
	Master master(io_context, config, rng);
}
