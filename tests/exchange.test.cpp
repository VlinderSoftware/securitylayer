#include "catch.hpp"
#include "../outstation.hpp"
#include "../master.hpp"
#include "deterministicrandomnumbergenerator.hpp"

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "Outstation sends an initial unsolicited response" "[unsol]") {
	GIVEN( "An Outstation stack" ) {
		io_context ioc;
		Config default_config;
		Tests::DeterministicRandomNumberGenerator rng;
		Outstation outstation(ioc, default_config, rng);

		THEN( "The Outstation will be in the INITIAL state" ) {
			REQUIRE( outstation.getState() == Outstation::initial__ );
		}

		WHEN( "the Application Layer tries to send an APDU" ) {
			unsigned char apdu_buffer[2048];
			mutable_buffer apdu(apdu_buffer, sizeof(apdu_buffer));
			rng.generate(apdu); // NOTE: we really don't care about the contents of the APDU here
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
				REQUIRE( outstation.getStatistic(Statistics::error_messages_sent__) == 0 );
				REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 0 );
				REQUIRE( outstation.getStatistic(Statistics::authenticated_apdus_sent__) == 0 );	
				static_assert(static_cast< int >(Statistics::statistics_count__) == 6, "New statistic added?");
			}
			WHEN( "The Master receives it" ) {
				Master master(ioc, default_config, rng);
				REQUIRE( master.getState() == Master::initial__ );
				
				auto spdu(outstation.getSPDU());
				master.postSPDU(spdu);
				THEN( "The Master should be in the EXPECT_SESSION_START_RESPONSE state" ) {
					REQUIRE( master.getState() == Master::expect_session_start_response__ );
				}
				THEN( "The Master should not present anything as an APDU" ) {
					REQUIRE( !master.pollAPDU() );
				}
				THEN( "The Master should send back a SessionStartRequest" ) {
					REQUIRE( master.pollSPDU() );
					auto spdu(master.getSPDU());
					REQUIRE( !master.pollSPDU() );
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
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
#if defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL
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
				//TODO check Master stats
				//TODO test cases where the Outstation sent its RequestSessionInitation message with sequence numbers 
				//     other than 1, according to OPTION_IGNORE_OUTSTATION_SEQ_ON_REQUEST_SESSION_INITIATION
				WHEN( "The Outstation receives the Master's response" ) {
					spdu = master.getSPDU();
					outstation.postSPDU(spdu);
					THEN( "The Outstation should go to the EXPECT_SET_KEYS state" ) {
						REQUIRE( outstation.getState() == Outstation::expect_set_keys__ );
					}
					THEN( "The Outstation should not present an APDU" ) {
						REQUIRE( !outstation.pollAPDU() );
					}
					THEN( "The Outstation should present an SPDU" ) {
						REQUIRE( outstation.pollSPDU() );
					}
					THEN( "The Outstation should send back a SessionStartResponse" ) {
						REQUIRE( outstation.pollSPDU() );
						auto spdu(outstation.getSPDU());
						REQUIRE( !outstation.pollSPDU() );
#if (!defined(OPTION_MASTER_SETS_KWA_AND_MAL) || !OPTION_MASTER_SETS_KWA_AND_MAL) || (defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL && defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS)
						REQUIRE( spdu.size() == 22 );
#else
						REQUIRE( spdu.size() == 20 );
#endif
						unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
						REQUIRE( spdu_bytes[0] == 0xc0 );
						REQUIRE( spdu_bytes[1] == 0x80 );
						REQUIRE( spdu_bytes[2] == 0x01 );
						REQUIRE( spdu_bytes[3] == 0x03 );
						REQUIRE( spdu_bytes[4] == 0x01 );
						REQUIRE( spdu_bytes[5] == 0x00 );
						REQUIRE( spdu_bytes[6] == 0x00 );
						REQUIRE( spdu_bytes[7] == 0x00 );
#if (!defined(OPTION_MASTER_SETS_KWA_AND_MAL) || !OPTION_MASTER_SETS_KWA_AND_MAL) || (defined(OPTION_MASTER_SETS_KWA_AND_MAL) && OPTION_MASTER_SETS_KWA_AND_MAL && defined(OPTION_MASTER_KWA_AND_MAL_ARE_HINTS) && OPTION_MASTER_KWA_AND_MAL_ARE_HINTS)
						REQUIRE( spdu_bytes[8] == 0x02 );
						REQUIRE( spdu_bytes[9] == 0x04 );
						REQUIRE( spdu_bytes[10] == 0x3C );
						REQUIRE( spdu_bytes[11] == 0x00 );
						REQUIRE( spdu_bytes[12] == 0x00 );
						REQUIRE( spdu_bytes[13] == 0x00 );
						REQUIRE( spdu_bytes[14] == 0x00 );
						REQUIRE( spdu_bytes[15] == 0x10 );
						REQUIRE( spdu_bytes[16] == 0x04 );
						REQUIRE( spdu_bytes[17] == 0x00 );
						REQUIRE( spdu_bytes[18] == 0x79 );
						REQUIRE( spdu_bytes[19] == 0x28 );
						REQUIRE( spdu_bytes[20] == 0x11 );
						REQUIRE( spdu_bytes[21] == 0xc8 );
#else
						REQUIRE( spdu_bytes[ 8] == 0x3C );
						REQUIRE( spdu_bytes[ 9] == 0x00 );
						REQUIRE( spdu_bytes[10] == 0x00 );
						REQUIRE( spdu_bytes[11] == 0x00 );
						REQUIRE( spdu_bytes[12] == 0x00 );
						REQUIRE( spdu_bytes[13] == 0x20 );
						REQUIRE( spdu_bytes[14] == 0x04 );
						REQUIRE( spdu_bytes[15] == 0x00 );
						REQUIRE( spdu_bytes[16] == 0x79 );
						REQUIRE( spdu_bytes[17] == 0x28 );
						REQUIRE( spdu_bytes[18] == 0x11 );
						REQUIRE( spdu_bytes[19] == 0xc8 );
#endif
					}
					WHEN( "The Master receives the SessionStartResponse" ) {
						auto spdu(outstation.getSPDU());
						master.postSPDU(spdu);
						THEN( "The Master should go to the EXPECT_SESSION_ACK state" ) {
							REQUIRE( master.getState() == SecurityLayer::expect_session_ack__ );
						}
						THEN( "The Master will send SetSessionKeys message" ) {
							auto spdu(master.getSPDU());
							REQUIRE( spdu.size() == 98 );
							unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
							REQUIRE( spdu_bytes[0] == 0xc0 );
							REQUIRE( spdu_bytes[1] == 0x80 );
							REQUIRE( spdu_bytes[2] == 0x01 );
							REQUIRE( spdu_bytes[3] == 0x04 );
							REQUIRE( spdu_bytes[4] == 0x01 );
							REQUIRE( spdu_bytes[5] == 0x00 );
							REQUIRE( spdu_bytes[6] == 0x00 );
							REQUIRE( spdu_bytes[7] == 0x00 );
							unsigned char const expected[] = {
							  0x58, 0x00 
							, 0x58, 0x02, 0x67, 0x64, 0x0b, 0x24, 0xc8, 0x86, 0x59, 0x44, 0xaa, 0x06, 0x4b, 0x28, 0xf0, 0x00
							, 0xb9, 0xe6, 0x0f, 0x85, 0xbc, 0x0a, 0xe6, 0xbd, 0x3a, 0xe2, 0x43, 0xe7, 0x65, 0x75, 0x06, 0xba
							, 0xfc, 0x05, 0xbc, 0x56, 0x00, 0x74, 0x50, 0x6f, 0xc5, 0x08, 0x19, 0x6e, 0xa5, 0x10, 0xa0, 0x22
							, 0xc0, 0x6f, 0xb9, 0x04, 0x1f, 0x96, 0x04, 0x25, 0x8c, 0xf6, 0xd9, 0x15, 0x5d, 0xc4, 0x6e, 0x32
							, 0x9f, 0x8f, 0x54, 0xd1, 0x57, 0x76, 0xb3, 0x85, 0xe6, 0xcd, 0xa7, 0xb1, 0x0d, 0xec, 0x74, 0xe7
							, 0x9c, 0x26, 0x6e, 0x87, 0xe0, 0x01, 0x31, 0xec 
							};
							static_assert(sizeof(expected) == 90, "unexpected size for expected response");
							REQUIRE( memcmp(spdu_bytes + 8, expected, sizeof(expected)) == 0 );
						}
						//TODO check the statistics
						//TODO check invalid messages (things that should provoke error returns)
						//TODO check with the wrong sequence number
					}
				}
				//TODO test that a session start request from a broadcast address is ignored
				//TODO check statistics
				//TODO check invalid messages (things that should provoke error returns)
			}
		}
	}
}

