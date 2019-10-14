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
                WHEN( "The Master is reset and sends another APDU" ) {
                    master.onApplicationReset();
                    master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
                    THEN( "A session is re-initialized" ) {
                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        REQUIRE( master.getState() == Master::active__ );
                        REQUIRE( outstation.getState() == Outstation::active__ );
                    }
                    THEN( "While a session is re-initialized, if an APDU is sent by the Outstation application layer, it will get through the Outstation" ) {
                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                        auto apdu_carrying_spdu(outstation.getSPDU());
                        unsigned char const *apdu_carrying_spdu_bytes(static_cast< unsigned char const * >(apdu_carrying_spdu.data()));
                        REQUIRE( apdu_carrying_spdu_bytes[ 0] == 0xc0 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 1] == 0x80 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 2] == 0x01 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 3] == 0x06 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 4] == 0x03 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 5] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 6] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 7] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 8] == 0x04 );
                        REQUIRE( apdu_carrying_spdu_bytes[ 9] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[10] == 0xc9 );
                        REQUIRE( apdu_carrying_spdu_bytes[11] == 0x81 );
                        REQUIRE( apdu_carrying_spdu_bytes[12] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[13] == 0x00 );
                        REQUIRE( apdu_carrying_spdu_bytes[14] == 0xc3 );
                        REQUIRE( apdu_carrying_spdu_bytes[15] == 0xfb );
                        REQUIRE( apdu_carrying_spdu_bytes[16] == 0x76 );
                        REQUIRE( apdu_carrying_spdu_bytes[17] == 0x94 );
                        REQUIRE( apdu_carrying_spdu_bytes[18] == 0x75 );
                        REQUIRE( apdu_carrying_spdu_bytes[19] == 0x05 );
                        REQUIRE( apdu_carrying_spdu_bytes[20] == 0xfe );
                        REQUIRE( apdu_carrying_spdu_bytes[21] == 0x85 );
                        REQUIRE( apdu_carrying_spdu_bytes[22] == 0xdf );
                        REQUIRE( apdu_carrying_spdu_bytes[23] == 0xa8 );
                        REQUIRE( apdu_carrying_spdu_bytes[24] == 0xaa );
                        REQUIRE( apdu_carrying_spdu_bytes[25] == 0xf6 );
                        REQUIRE( apdu_carrying_spdu_bytes[26] == 0xd2 );
                        REQUIRE( apdu_carrying_spdu_bytes[27] == 0xed );
                        REQUIRE( apdu_carrying_spdu_bytes[28] == 0xa1 );
                        REQUIRE( apdu_carrying_spdu_bytes[29] == 0x15 );
                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        REQUIRE( master.getState() == Master::active__ );
                        REQUIRE( outstation.getState() == Outstation::active__ );
                    }
                }
                WHEN( "The Outstation sends a few unsolicited responses (that don't necessarily arrive at the Master), the sequence number will go up as expected" ) {
                    for (unsigned int i(0); i < 20; ++i)
                    {
                        outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                        ++expected_seq;
                        spdu = outstation.getSPDU();
                        REQUIRE( getSPDUSequenceNumber(spdu) == expected_seq );
                    }
                }
                WHEN( "The Master sends a few messages that don't arrive at the Outstation, the sequence number will go up as expected" ) {
                    for (unsigned int i(0); i < 20; ++i)
                    {
                        master.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                        ++expected_seq;
                        spdu = master.getSPDU();
                        REQUIRE( getSPDUSequenceNumber(spdu) == expected_seq );
                    }
                }
                WHEN( "messages from the Master arrive at the Outstation out-of-order" ) {
                    master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
                    spdu = master.getSPDU();
                    vector< unsigned char > buffer(spdu.size());
                    memcpy(&buffer[0], spdu.data(), spdu.size());
                    const_buffer old_spdu(&buffer[0], buffer.size());
                    master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
                    spdu = master.getSPDU();
                    THEN( "The first to arrive is accepted, the second (held back) is discarded" ) {
                        outstation.postSPDU(spdu);
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_received__) == 4 );
				        REQUIRE( outstation.getStatistic(Statistics::discarded_messages__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::authenticated_apdus_sent__) == 1 );	
				        static_assert(static_cast< int >(Statistics::statistics_count__) == 6, "New statistic added?");
                        outstation.postSPDU(old_spdu);
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_received__) == 5 );
				        REQUIRE( outstation.getStatistic(Statistics::discarded_messages__) == 1 );
				        REQUIRE( outstation.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::authenticated_apdus_sent__) == 1 );	
                    }
                }
                WHEN( "messages from the Outstation arrive at the Master out-of-order" ) {
                    outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                    spdu = outstation.getSPDU();
                    vector< unsigned char > buffer(spdu.size());
                    memcpy(&buffer[0], spdu.data(), spdu.size());
                    const_buffer old_spdu(&buffer[0], buffer.size());
                    outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                    spdu = outstation.getSPDU();
                    THEN( "The first to arrive is accepted, the second (held back) is discarded" ) {
                        master.postSPDU(spdu);
				        REQUIRE( master.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( master.getStatistic(Statistics::total_messages_received__) == 4 );
				        REQUIRE( master.getStatistic(Statistics::discarded_messages__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::authenticated_apdus_sent__) == 1 );	
				        static_assert(static_cast< int >(Statistics::statistics_count__) == 6, "New statistic added?");
                        master.postSPDU(old_spdu);
				        REQUIRE( master.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( master.getStatistic(Statistics::total_messages_received__) == 5 );
				        REQUIRE( master.getStatistic(Statistics::discarded_messages__) == 1 );
				        REQUIRE( master.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::authenticated_apdus_sent__) == 1 );	
                    }
                }
            }
        }
    }
}
