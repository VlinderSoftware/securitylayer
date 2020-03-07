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

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "Master sets up a session, then exchanges messages until the keys expire" "[session]") {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll
    unsigned char const response_bytes[] = { 0xC9, 0x81, 0x00, 0x00 }; // null response

    GIVEN( "A new Master and a new Outstation" ) {
		io_context ioc;
		Config default_config;
        default_config.session_key_change_count_ = 1000;
		Tests::DeterministicRandomNumberGenerator rng;
		Master master(ioc, 0/* association ID */, default_config, rng);
		Outstation outstation(ioc, 0/* association ID */, default_config, rng);

        WHEN( "A session is set up and an APDU pushed through by the Master" ) {
            bool done(false);
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            
            auto master_update_result(master.update());
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            auto outstation_update_result(outstation.update());
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::initial__ );
            REQUIRE( outstation.getState() == SecurityLayer::initial__ );
            
            master.postAPDU(apdu_to_post);

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::initial__ );
            
            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::active__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::active__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            auto received_apdu(outstation.getAPDU());

            THEN( "With both sides configured to allow for 1000 messages, the Master can send 999 more messages without fail" ) {
                for (unsigned int i(0); i < 999; ++i)
                {
                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    master.postAPDU(apdu_to_post);

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    outstation.postSPDU(master.getSPDU());

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    received_apdu = outstation.getAPDU();
                }

                WHEN( "The session has been thusly used" ) {
                    THEN( "The next APDU from the Master should provoke a new SessionStartRequest" ) {
                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::active__ );
                        REQUIRE( outstation.getState() == SecurityLayer::active__ );

                        master.postAPDU(apdu_to_post);

                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                        REQUIRE( outstation.getState() == SecurityLayer::active__ );

                        auto the_spdu(master.getSPDU());
                        outstation.postSPDU(the_spdu);

                        THEN( "An APDU in the other direction should still go through without issue" ) {
                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );
                            
                            // simulate a bug in the surrounding code: it should have fetched the SPDU. This also simulates a dropped SPDU. We don't care for this test
                            outstation.postAPDU(apdu_to_post);

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );

                            master.postSPDU(outstation.getSPDU());

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );
                        }
                    }
                }
            }
        }
        WHEN( "A session is set up and an APDU pushed through by the Outstation" ) {
            bool done(false);
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            
            auto master_update_result(master.update());
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            auto outstation_update_result(outstation.update());
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::initial__ );
            REQUIRE( outstation.getState() == SecurityLayer::initial__ );
            
            outstation.postAPDU(apdu_to_post);

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::initial__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );
            
            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::expect_session_key_change_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::expect_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::active__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::active__ );
            REQUIRE( outstation.getState() == SecurityLayer::active__ );

            auto received_apdu(master.getAPDU());

            THEN( "With both sides configured to allow for 1000 messages, the Master can send 999 more messages without fail" ) {
                for (unsigned int i(0); i < 999; ++i)
                {
                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    outstation.postAPDU(apdu_to_post);

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    master.postSPDU(outstation.getSPDU());

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::active__ );
                    REQUIRE( outstation.getState() == SecurityLayer::active__ );

                    received_apdu = master.getAPDU();
                }

                WHEN( "The session has been thusly used" ) {
                    THEN( "The next APDU from the Master should provoke a new SessionStartRequest" ) {
                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::active__ );
                        REQUIRE( outstation.getState() == SecurityLayer::active__ );

                        outstation.postAPDU(apdu_to_post);

                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                        REQUIRE( master.getState() == SecurityLayer::active__ );
                        REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );

                        auto the_spdu(outstation.getSPDU());
                        master.postSPDU(the_spdu);

                        THEN( "An APDU in the other direction should still go through without issue" ) {
                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );
                            
                            // simulate a bug in the surrounding code: it should have fetched the SPDU. This also simulates a dropped SPDU. We don't care for this test
                            master.postAPDU(apdu_to_post);

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );

                            outstation.postSPDU(master.getSPDU());

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::expect_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::expect_session_start_request__ );
                        }
                    }
                }
            }
        }
    }
}
