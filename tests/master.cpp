#include "catch.hpp"
#include "../master.hpp"

using namespace DNP3SAv6;

TEST_CASE( "Master: try to create an instance", "[master]" ) {
	boost::asio::io_context io_context;
	Config config;
	Master master(io_context, config);
}
