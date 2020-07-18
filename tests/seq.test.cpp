/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "catch.hpp"
#include "../outstation.hpp"
#include "../master.hpp"
#include "deterministicrandomnumbergenerator.hpp"
#include "../exceptions/contract.hpp"
#include "updatekeystorestub.hpp"
#include "certificatestorestub.hpp"

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

namespace {
    uint16_t getSPDUSequenceNumber(const_buffer const &spdu)
    {
        pre_condition(spdu.size() >= (8/*SPDU header size*/));
        uint16_t seq;
        memcpy(&seq, static_cast< unsigned char const* >(spdu.data()) + 6, sizeof(seq));
        return seq;
    }
}

SCENARIO( "Master sets up a session, then exchanges a few messages" "[seq]") {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll
    unsigned char const response_bytes[] = { 0xC9, 0x81, 0x00, 0x00 }; // null response

    GIVEN( "A new Master and a new Outstation" ) {
		io_context ioc;
		Config default_config;
		default_config.master_outstation_association_name_.association_id_ = 1;
		Tests::DeterministicRandomNumberGenerator rng;
        Tests::UpdateKeyStoreStub update_key_store;
        Tests::CertificateStoreStub certificate_store;
		Master master(ioc, default_config, rng, update_key_store, certificate_store);
		Outstation outstation(ioc, default_config, rng, update_key_store, certificate_store);

        WHEN( "A session is set up and an APDU pushed through" ) {
            master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            REQUIRE( master.getState() == Master::normal_operation__ );
            REQUIRE( outstation.getState() == Outstation::normal_operation__ );

            uint32_t expected_seq(1);

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
                        REQUIRE( master.getState() == Master::normal_operation__ );
                        REQUIRE( outstation.getState() == Outstation::normal_operation__ );
                    }
                    THEN( "While a session is re-initialized, if an APDU is sent by the Outstation application layer, it will get through the Outstation" ) {
                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        outstation.postAPDU(const_buffer(response_bytes, sizeof(response_bytes)));
                        auto apdu_carrying_spdu(outstation.getSPDU());
                        unsigned char const *apdu_carrying_spdu_bytes(static_cast< unsigned char const * >(apdu_carrying_spdu.data()));
                        unsigned char const expected[] = {
                              0xc0, 0x80, 0x40, 0x06, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 
                            , 0x04, 0x00
                            , 0xc9, 0x81, 0x00, 0x00 
                            , 0xa9, 0x00, 0xc9, 0x1d, 0x15, 0x57, 0x13, 0x01, 0x73, 0xc8, 0xdf, 0xac, 0x6c, 0x32, 0x9c, 0xaf 
                            };
                        REQUIRE( memcmp(apdu_carrying_spdu_bytes, expected, sizeof(expected)) == 0 );

                        outstation.postSPDU(master.getSPDU());
                        master.postSPDU(outstation.getSPDU());
                        REQUIRE( master.getState() == Master::normal_operation__ );
                        REQUIRE( outstation.getState() == Outstation::normal_operation__ );
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
				        REQUIRE( outstation.getStatistic(Statistics::secure_messages_sent_) == 1 );	
				        REQUIRE( outstation.getStatistic(Statistics::wrong_association_id__) == 0 );	
				        static_assert(static_cast< int >(Statistics::statistics_count__) == 7, "New statistic added?");
                        outstation.postSPDU(old_spdu);
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( outstation.getStatistic(Statistics::total_messages_received__) == 5 );
				        REQUIRE( outstation.getStatistic(Statistics::discarded_messages__) == 1 );
				        REQUIRE( outstation.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( outstation.getStatistic(Statistics::secure_messages_sent_) == 1 );	
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
				        REQUIRE( master.getStatistic(Statistics::secure_messages_sent_) == 1 );	
				        REQUIRE( master.getStatistic(Statistics::wrong_association_id__) == 0 );	
				        static_assert(static_cast< int >(Statistics::statistics_count__) == 7, "New statistic added?");
                        master.postSPDU(old_spdu);
				        REQUIRE( master.getStatistic(Statistics::total_messages_sent__) == 3 );
				        REQUIRE( master.getStatistic(Statistics::total_messages_received__) == 5 );
				        REQUIRE( master.getStatistic(Statistics::discarded_messages__) == 1 );
				        REQUIRE( master.getStatistic(Statistics::error_messages_sent__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::unexpected_messages__) == 0 );
				        REQUIRE( master.getStatistic(Statistics::secure_messages_sent_) == 1 );	
                    }
                }
            }
        }
    }
}
//TODO test that the sequence number can't roll over during the session: a session shall not allow for more than 65535 messages (incoming and outgoing combined)