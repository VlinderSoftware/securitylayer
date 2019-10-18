#include "catch.hpp"
#include "../outstation.hpp"
#include "../master.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../exceptions/contract.hpp"

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "Master sets up a session, exchanges a few messages, the restarts a session" "[session-restart]") {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll
    unsigned char const response_bytes[] = { 0xC9, 0x81, 0x00, 0x00 }; // null response

    GIVEN( "A new Master and a new Outstation" ) {
		io_context ioc;
		Config default_config;
		Tests::DeterministicRandomNumberGenerator rng;
		Master master(ioc, default_config, rng);
		Outstation outstation(ioc, default_config, rng);

        WHEN( "A session is set up and a few APDUs pushed through" ) {
            master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            REQUIRE( master.getState() == Master::active__ );
            REQUIRE( outstation.getState() == Outstation::active__ );

            uint32_t expected_seq(1);

            master.update();
            outstation.postSPDU(master.getSPDU());
            outstation.getAPDU();

            outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
            master.postSPDU(outstation.getSPDU());
            master.getAPDU();

            for (unsigned int i(0); i < 100; ++i)
            {
                master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
                outstation.postSPDU(master.getSPDU());
                outstation.getAPDU();

                outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                master.postSPDU(outstation.getSPDU());
                master.getAPDU();
            }

            WHEN( "the Application tells the Master to start a new session" ) {
                master.startNewSession();
                THEN( "the Master will send a SessionStartRequest message" ) {
					auto spdu(master.getSPDU());
                    REQUIRE( spdu.size() == 18 );
					unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
					REQUIRE( spdu_bytes[0] == 0xc0 );
					REQUIRE( spdu_bytes[1] == 0x80 );
					REQUIRE( spdu_bytes[2] == 0x01 );
					REQUIRE( spdu_bytes[3] == 0x02 );
                }
                THEN( "the Master will still accept new authenticated APDUs" ) {
                    outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                    master.postSPDU(outstation.getSPDU());
                    REQUIRE( master.pollAPDU() );
                }
                THEN( "The Master can still send authenticated APDUs" ) {
                    master.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                    outstation.postSPDU(master.getSPDU());
                    REQUIRE( outstation.pollAPDU() );
                }
            }
        }
    }
}
