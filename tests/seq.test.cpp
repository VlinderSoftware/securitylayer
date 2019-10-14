#include "catch.hpp"
#include "../outstation.hpp"
#include "../master.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../exceptions/contract.hpp"

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

namespace {
    uint32_t getSPDUSequenceNumber(const_buffer const &spdu)
    {
        pre_condition(spdu.size() >= 8);
        uint32_t seq;
        memcpy(&seq, static_cast< unsigned char const* >(spdu.data()) + 4, 4);
        return seq;
    }
}

SCENARIO( "Master sets up a session, then exchanges a few messages" "[session]") {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll
    unsigned char const response_bytes[] = { 0xC9, 0x81, 0x00, 0x00 }; // null response

    GIVEN( "A new Master and a new Outstation" ) {
		io_context ioc;
		Config default_config;
		Tests::DeterministicRandomNumberGenerator rng;
		Master master(ioc, default_config, rng);
		Outstation outstation(ioc, default_config, rng);

        WHEN( "A session is set up and an APDU pushed through" ) {
            master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            REQUIRE( master.getState() == Master::active__ );
            REQUIRE( outstation.getState() == Outstation::active__ );

            uint32_t expected_seq(2);

            master.update();
            auto spdu(master.getSPDU());
            outstation.postSPDU(spdu);
            outstation.getAPDU();
            THEN( "SPDU sequence number is as expected" ) {
                REQUIRE( getSPDUSequenceNumber(spdu) == expected_seq );
            }
            THEN( "Master and Outstation pipes are empty" ) {
                REQUIRE( !master.pollAPDU() );
                REQUIRE( !master.pollSPDU() );
                REQUIRE( !outstation.pollAPDU() );
                REQUIRE( !outstation.pollSPDU() );
            }
            WHEN( "The Outstation responds" ) {
                outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                spdu = outstation.getSPDU();
                master.postSPDU(spdu);
                master.getAPDU();
                THEN( "SPDU sequence number is as expected" ) {
                    REQUIRE( getSPDUSequenceNumber(spdu) == expected_seq );
                }
                THEN( "Master and Outstation pipes are empty" ) {
                    REQUIRE( !master.pollAPDU() );
                    REQUIRE( !master.pollSPDU() );
                    REQUIRE( !outstation.pollAPDU() );
                    REQUIRE( !outstation.pollSPDU() );
                }
                //TODO test the outstation sending a few unsols
                //TODO test the master sending a few messages that don't arrive
                //TODO test messages arriving out-of-order at the outstation (i.e. hold-back-and-replay)
                //TODO test messages arriving out-of-order at the master (i.e. hold-back-and-replay)
            }
        }
    }
}
