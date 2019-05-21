#include "catch.hpp"
#include "../config.h"
#include "../outstation.hpp"
#include "../master.hpp"
#include <sodium.h>

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "Outstation sends an initial unsolicited response" "[unsol]") {
	GIVEN( "An Outstation stack" ) {
		io_context ioc;
		Config default_config;
		Outstation outstation(ioc, default_config);

		THEN( "The Outstation will be in the INITIAL state" ) {
			REQUIRE( outstation.getState() == Outstation::initial__ );
		}

		WHEN( "the Application Layer tries to send an APDU" ) {
			unsigned char apdu_buffer[2048];
			randombytes_buf(apdu_buffer, sizeof(apdu_buffer));
			const_buffer apdu(apdu_buffer, sizeof(apdu_buffer));
			outstation.postAPDU(apdu);
			THEN( "The Outstation state will be EXPECT_SESSION_START_REQUEST" ) {
				REQUIRE( outstation.getState() == Outstation::expect_session_start_request__ );
			}
			THEN( "The Outstation will attempt to send a RequestSessionInitiation message" ) {
				REQUIRE( outstation.pollSPDU() );
				auto spdu(outstation.getSPDU());
				REQUIRE( !outstation.pollSPDU() );
				REQUIRE( spdu.size() == 8 );
				unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
				REQUIRE( spdu_bytes[0] == 0xc0 );
				REQUIRE( spdu_bytes[1] == 0x80 );
				REQUIRE( spdu_bytes[2] == 0x01 );
				REQUIRE( spdu_bytes[3] == 0x01 );
				REQUIRE( spdu_bytes[4] == 0x01 );
				REQUIRE( spdu_bytes[5] == 0x00 );
				REQUIRE( spdu_bytes[6] == 0x00 );
				REQUIRE( spdu_bytes[7] == 0x00 );
			}
			THEN( "The TotalMessagesSent statistic should be at one, others zero" ) {
				REQUIRE( outstation.getStatistic(Statistics::total_messages_sent__) == 1 );
				REQUIRE( outstation.getStatistic(Statistics::total_messages_received__) == 0 );
				REQUIRE( outstation.getStatistic(Statistics::discarded_messages__) == 0 );
			}
			WHEN( "The Master receives it" ) {
				Master master(ioc, default_config);
				REQUIRE( master.getState() == Master::initial__ );
				
				auto spdu(outstation.getSPDU());
				master.postSPDU(spdu);
				THEN( "The Master should be in the EXPECT_SESSION_START_RESPONSE state" ) {
					REQUIRE( master.getState() == Master::expect_session_start_response__ );
				}
				THEN( "The Master should not present anything as an APDU" ) {
					REQUIRE( !master.pollAPDU() );
				}
				THEN( "The Master should send back a SessionInitiationRequest" ) {
					REQUIRE( master.pollSPDU() );
					auto spdu(master.getSPDU());
					REQUIRE( !master.pollSPDU() );
#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
					REQUIRE( spdu.size() == 18 );
#else
					REQUIRE( spdu.size() == 16 );
#endif
					unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
					REQUIRE( spdu_bytes[0] == 0xc0 );
					REQUIRE( spdu_bytes[1] == 0x80 );
					REQUIRE( spdu_bytes[2] == 0x01 );
					REQUIRE( spdu_bytes[3] == 0x02 );
					REQUIRE( spdu_bytes[4] == 0x01 );
					REQUIRE( spdu_bytes[5] == 0x00 );
					REQUIRE( spdu_bytes[6] == 0x00 );
					REQUIRE( spdu_bytes[7] == 0x00 );
					REQUIRE( spdu_bytes[8] == 0x06 );
					REQUIRE( spdu_bytes[9] == 0x00 );
#ifdef OPTION_MASTER_SETS_KWA_AND_MAL
					REQUIRE( spdu_bytes[10] == 0x02 );
					REQUIRE( spdu_bytes[11] == 0x04 );
					REQUIRE( spdu_bytes[12] == 0x3C );
					REQUIRE( spdu_bytes[13] == 0x00 );
					REQUIRE( spdu_bytes[14] == 0x00 );
					REQUIRE( spdu_bytes[15] == 0x00 );
					REQUIRE( spdu_bytes[16] == 0x00 );
					REQUIRE( spdu_bytes[17] == 0x10 );
#else
					REQUIRE( spdu_bytes[10] == 0x3C );
					REQUIRE( spdu_bytes[11] == 0x00 );
					REQUIRE( spdu_bytes[12] == 0x00 );
					REQUIRE( spdu_bytes[13] == 0x00 );
					REQUIRE( spdu_bytes[14] == 0x00 );
					REQUIRE( spdu_bytes[15] == 0x10 );
#endif
				}
				//TODO test cases where the Outstation sent its RequestSessionInitation message with sequence numbers 
				//     other than 1, according to OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
			}
		}
	}
}
