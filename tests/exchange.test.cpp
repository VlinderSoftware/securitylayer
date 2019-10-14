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
							REQUIRE( master.getState() == SecurityLayer::expect_session_confirmation__ );
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
                            , 0x22, 0x3d, 0x4b, 0xd6, 0x49, 0xd8, 0x47, 0x6b, 0x58, 0x81, 0xa6, 0x59, 0x91, 0xb4, 0xe0, 0xc5
                            , 0x15, 0x33, 0x7a, 0xc6, 0x5e, 0xbb, 0x57, 0xe2, 0x97, 0x73, 0xb4, 0x27, 0x7b, 0xbf, 0x3f, 0xd6
                            , 0x87, 0xe5, 0xfd, 0x53, 0x50, 0x56, 0x9a, 0x43, 0x0e, 0x56, 0xf0, 0xdd, 0xd5, 0x57, 0x0f, 0x10
                            , 0x79, 0x2d, 0x4b, 0x59, 0x13, 0xa2, 0xce, 0x75, 0xe4, 0x1f, 0xad, 0x63, 0xa0, 0x49, 0xff, 0xe1
                            , 0xb3, 0x8e, 0x7a, 0xfa, 0x5a, 0x01, 0xcf, 0x39, 0xf5, 0xe3, 0xf7, 0xf7, 0xeb, 0xcd, 0xdb, 0x72
                            , 0x62, 0xb8, 0x03, 0xf9, 0xbf, 0x8f, 0x9d, 0xad
							};
							static_assert(sizeof(expected) == 90, "unexpected size for expected response");
							REQUIRE( memcmp(spdu_bytes + 8, expected, sizeof(expected)) == 0 );
						}
						//TODO check the statistics
						//TODO check invalid messages (things that should provoke error returns)
						//TODO check with the wrong sequence number
                        WHEN( "The Outstation receives the SetSessionKeys message" ) {
                            auto spdu(master.getSPDU());
                            outstation.postSPDU(spdu);
                            THEN( "The outstation should go to the ACTIVE state" ) {
        						REQUIRE( outstation.getState() == Outstation::active__ );
                            }
                            THEN( "The Outstation will attempt to send a SessionConfirmation message" ) {
                                REQUIRE( outstation.pollSPDU() );
				                auto spdu(outstation.getSPDU());
				                REQUIRE( !outstation.pollSPDU() );
				                REQUIRE( spdu.size() == 26 );
				                unsigned char const *spdu_bytes(static_cast< unsigned char const * >(spdu.data()));
				                REQUIRE( spdu_bytes[0] == 0xc0 );
				                REQUIRE( spdu_bytes[1] == 0x80 );
				                REQUIRE( spdu_bytes[2] == 0x01 );
				                REQUIRE( spdu_bytes[3] == 0x05 );
				                REQUIRE( spdu_bytes[4] == 0x01 );
				                REQUIRE( spdu_bytes[5] == 0x00 );
				                REQUIRE( spdu_bytes[6] == 0x00 );
				                REQUIRE( spdu_bytes[7] == 0x00 );
                                REQUIRE( spdu_bytes[8] == 0x10 );
                                REQUIRE( spdu_bytes[9] == 0x00 );
                                REQUIRE( spdu_bytes[10] == 0xbc );
                                REQUIRE( spdu_bytes[11] == 0x1d );
                                REQUIRE( spdu_bytes[12] == 0x81 );
                                REQUIRE( spdu_bytes[13] == 0x6a );
                                REQUIRE( spdu_bytes[14] == 0x73 );
                                REQUIRE( spdu_bytes[15] == 0xd1 );
                                REQUIRE( spdu_bytes[16] == 0x1b );
                                REQUIRE( spdu_bytes[17] == 0xd4 );
                                REQUIRE( spdu_bytes[18] == 0x6e );
                                REQUIRE( spdu_bytes[19] == 0xfb );
                                REQUIRE( spdu_bytes[20] == 0xab );
                                REQUIRE( spdu_bytes[21] == 0xf9 );
                                REQUIRE( spdu_bytes[22] == 0xf5 );
                                REQUIRE( spdu_bytes[23] == 0x78 );
                                REQUIRE( spdu_bytes[24] == 0x0e );
                                REQUIRE( spdu_bytes[25] == 0x12 );
                            }
                            //TODO check outstation statistics
                            WHEN( "The Outstation to sends a SessionConfirmation message" ) {
                                auto spdu(outstation.getSPDU());
                                THEN( "The Outstation has prepared the authenticated-APDU SPDU" )
                                {
                                    outstation.update();
                                    REQUIRE( outstation.pollSPDU() ); // for the pending APDU
                                }
                                WHEN( "The Master receives it" ) {
                                    master.postSPDU(spdu);
                                    THEN( "The Master should go to the ACTIVE state" ) {
                                        REQUIRE( master.getState() == SecurityLayer::active__ );
                                    }
                                    WHEN( "The Outstation canceled the APDU (timeout)" ) {
                                        outstation.onAPDUTimeout();
                                        THEN( "No SPDU will be pending" ) {
                                             REQUIRE( !outstation.pollSPDU() );
                                        }
                                    }
                                    WHEN( "The Outstation canceled the APDU (application reset)" ) {
                                        outstation.onApplicationReset();
                                        THEN( "No SPDU will be pending" ) {
                                             REQUIRE( !outstation.pollSPDU() );
                                        }
                                    }
                                    WHEN( "The Outstation canceled the APDU (cancel)" ) {
                                        outstation.cancelPendingAPDU();
                                        THEN( "No SPDU will be pending" ) {
                                             REQUIRE( !outstation.pollSPDU() );
                                        }
                                    }
                                }
                            }
                        }
					}
				}
				//TODO test that a session start request from a broadcast address is ignored
				//TODO check statistics
				//TODO check invalid messages (things that should provoke error returns)
			}
		}
	}
}

