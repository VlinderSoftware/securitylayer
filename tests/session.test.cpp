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

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "Master sets up a session, then exchanges messages until the keys expire" "[session]") {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll

    GIVEN( "A new Master and a new Outstation, configured for up to 1000 messages in either direction" ) {
		io_context ioc;
		Config default_config;
		default_config.master_outstation_association_name_.association_id_ = 1;
        default_config.session_key_change_count_ = 1000;
		Tests::DeterministicRandomNumberGenerator rng;
        Tests::UpdateKeyStoreStub update_key_store;
		Master master(ioc, default_config, rng, update_key_store);
		Outstation outstation(ioc, default_config, rng, update_key_store);

        WHEN( "A session is set up and an APDU pushed through by the Master" ) {
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            
            auto master_update_result(master.update());
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            auto outstation_update_result(outstation.update());
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );
            
            master.postAPDU(apdu_to_post);

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );
            
            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            auto received_apdu(outstation.getAPDU());

            THEN( "With both sides configured to allow for 1000 messages, the Master can send 999 more messages without fail" ) {
                for (unsigned int i(0); i < 999; ++i)
                {
                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                    REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                    master.postAPDU(apdu_to_post);

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                    REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                    outstation.postSPDU(master.getSPDU());

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
                    REQUIRE( master.getState() == ((i == 998) ? SecurityLayer::normal_operation__ : SecurityLayer::normal_operation__) );
                    REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                    received_apdu = outstation.getAPDU();
                }

                WHEN( "The session has been thusly used" ) {
                    THEN( "The next APDU from the Master should provoke a new SessionStartRequest" ) {
                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                        REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                        master.postAPDU(apdu_to_post);

                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                        REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                        auto the_spdu(master.getSPDU());
                        outstation.postSPDU(the_spdu);

                        THEN( "An APDU in the other direction should still go through without issue" ) {
                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );
                            
                            // simulate a bug in the surrounding code: it should have fetched the SPDU. This also simulates a dropped SPDU. We don't care for this test
                            outstation.postAPDU(apdu_to_post);

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );

                            master.postSPDU(outstation.getSPDU());

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );
                        }
                    }
                }
            }
        }
        WHEN( "A session is set up and an APDU pushed through by the Outstation" ) {
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            
            auto master_update_result(master.update());
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            auto outstation_update_result(outstation.update());
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );
            
            outstation.postAPDU(apdu_to_post);

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );
            
            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );

            outstation.postSPDU(master.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::wait_for_session_key_change_response__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            master.postSPDU(outstation.getSPDU());

            master_update_result = master.update();
            REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
            outstation_update_result = outstation.update();
            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

            auto received_apdu(master.getAPDU());

            THEN( "With both sides configured to allow for 1000 messages, the Master can send 999 more messages without fail" ) {
                for (unsigned int i(0); i < 999; ++i)
                {
                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                    REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                    outstation.postAPDU(apdu_to_post);

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                    REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                    REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                    master.postSPDU(outstation.getSPDU());

                    master_update_result = master.update();
                    REQUIRE( master_update_result.first == SecurityLayer::apdu_ready__ );
                    outstation_update_result = outstation.update();
                    REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                    REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                    REQUIRE( outstation.getState() == ((i == 998) ? SecurityLayer::normal_operation__ : SecurityLayer::normal_operation__) );

                    received_apdu = master.getAPDU();
                }

                WHEN( "The session has been thusly used" ) {
                    THEN( "The next APDU from the Master should provoke a new SessionStartRequest" ) {
                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                        REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                        REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );

                        outstation.postAPDU(apdu_to_post);

                        master_update_result = master.update();
                        REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                        outstation_update_result = outstation.update();
                        REQUIRE( outstation_update_result.first == SecurityLayer::spdu_ready__ );
                        REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                        REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );

                        auto the_spdu(outstation.getSPDU());
                        master.postSPDU(the_spdu);

                        THEN( "An APDU in the other direction should still go through without issue" ) {
                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );
                            
                            // simulate a bug in the surrounding code: it should have fetched the SPDU. This also simulates a dropped SPDU. We don't care for this test
                            master.postAPDU(apdu_to_post);

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::spdu_ready__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::wait__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );

                            outstation.postSPDU(master.getSPDU());

                            master_update_result = master.update();
                            REQUIRE( master_update_result.first == SecurityLayer::wait__ );
                            outstation_update_result = outstation.update();
                            REQUIRE( outstation_update_result.first == SecurityLayer::apdu_ready__ );
                            REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                            REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );
                        }
                    }
                }
            }
        }
    }

    /******************************************************************************************************************
     * NOTE: this test is timing-dependent in that if you run it in a debugger and hang around for more than five     *
     *       seconds, it may fail in unexpected ways because the session may time out where it's not expected.        *
     ******************************************************************************************************************/
    GIVEN( "A new Master and a new Outstation, configured for a session duration of up to five seconds on the Master" ) {
		io_context ioc;
		Config master_config;
        master_config.master_outstation_association_name_.association_id_ = 1;
		master_config.session_key_change_interval_ = 5;
		Config outstation_config;
        outstation_config.master_outstation_association_name_.association_id_ = 1;
		Tests::DeterministicRandomNumberGenerator rng;
        Tests::UpdateKeyStoreStub update_key_store;
		Master master(ioc, master_config, rng, update_key_store);
		Outstation outstation(ioc, outstation_config, rng, update_key_store);

        WHEN( "A session is set up and an APDU pushed through by the Master" ) {
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            master.postAPDU(apdu_to_post);
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            master.update();
            outstation.postSPDU(master.getSPDU());
            auto received_apdu(outstation.getAPDU());

            THEN( "The session can go on for five seconds" ) {
                boost::asio::steady_timer session_timer(ioc, std::chrono::milliseconds(4900));
                bool done(false);
                session_timer.async_wait([&](const boost::system::error_code& error){ done = !error; });

                boost::asio::steady_timer pump_timer(ioc, std::chrono::milliseconds(100));
                auto pump_an_apdu_through([&](const boost::system::error_code& error){
                        if (!done)
                        {
                            master.postAPDU(apdu_to_post);
                            outstation.postSPDU(master.getSPDU());
                            received_apdu = outstation.getAPDU();
                            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );
                            pump_timer.expires_at(pump_timer.expires_at() + std::chrono::milliseconds(100));
                        }
                    });
                while (!done)
                {
                    pump_timer.async_wait(pump_an_apdu_through);
                    ioc.run_one();
                }

                WHEN( "The session is thus expired" ) {
                    this_thread::sleep_for(std::chrono::milliseconds(200));

                    THEN( "The Master will send a SessionStartRequest when a new new APDU comes in" ) {
                        master.postAPDU(apdu_to_post);
                        outstation.postSPDU(master.getSPDU());
                        REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                        REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );
                    }

                    THEN( "The Master will reject an incoming SecureMessage as unexpected" ) {
                        outstation.postAPDU(apdu_to_post);
				        REQUIRE( master.getStatistic(Statistics::unexpected_messages__) == 0 );
                        master.postSPDU(outstation.getSPDU());
				        REQUIRE( master.getStatistic(Statistics::unexpected_messages__) == 1 );
                    }
                }
            }
        }
    }

    /******************************************************************************************************************
     * NOTE: this test is timing-dependent in that if you run it in a debugger and hang around for more than five     *
     *       seconds, it may fail in unexpected ways because the session may time out where it's not expected.        *
     ******************************************************************************************************************/
    GIVEN( "A new Master and a new Outstation, configured for a session duration of up to five seconds on the outstation" ) {
		io_context ioc;
		Config master_config;
        master_config.master_outstation_association_name_.association_id_ = 1;
		Config outstation_config;
        outstation_config.master_outstation_association_name_.association_id_ = 1;
		outstation_config.session_key_change_interval_ = 5;
		Tests::DeterministicRandomNumberGenerator rng;
        Tests::UpdateKeyStoreStub update_key_store;
		Master master(ioc, master_config, rng, update_key_store);
		Outstation outstation(ioc, outstation_config, rng, update_key_store);

        WHEN( "A session is set up and an APDU pushed through by the Master" ) {
            auto apdu_to_post(const_buffer(request_bytes, sizeof(request_bytes)));
            master.postAPDU(apdu_to_post);
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            outstation.postSPDU(master.getSPDU());
            master.postSPDU(outstation.getSPDU());
            master.update();
            outstation.postSPDU(master.getSPDU());
            auto received_apdu(outstation.getAPDU());

            THEN( "The session can go on for five seconds" ) {
                boost::asio::steady_timer session_timer(ioc, std::chrono::milliseconds(4900));
                bool done(false);
                session_timer.async_wait([&](const boost::system::error_code& error){ done = !error; });

                boost::asio::steady_timer pump_timer(ioc, std::chrono::milliseconds(100));
                auto pump_an_apdu_through([&](const boost::system::error_code& error){
                        if (!done)
                        {
                            master.postAPDU(apdu_to_post);
                            outstation.postSPDU(master.getSPDU());
                            received_apdu = outstation.getAPDU();
                            REQUIRE( master.getState() == SecurityLayer::normal_operation__ );
                            REQUIRE( outstation.getState() == SecurityLayer::normal_operation__ );
                            pump_timer.expires_at(pump_timer.expires_at() + std::chrono::milliseconds(100));
                        }
                    });
                while (!done)
                {
                    pump_timer.async_wait(pump_an_apdu_through);
                    ioc.run_one();
                }

                WHEN( "The session is thus expired" ) {
                    this_thread::sleep_for(std::chrono::milliseconds(200));

                    THEN( "The Outstation will send a SessionInitiation when a new new APDU comes in" ) {
                        outstation.postAPDU(apdu_to_post);
                        master.postSPDU(outstation.getSPDU());
                        REQUIRE( master.getState() == SecurityLayer::wait_for_session_start_response__ );
                        REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_start_request__ );
                    }

                    THEN( "The Outstation will reject an incoming SecureMessage as unexpected" ) {
                        master.postAPDU(apdu_to_post);
				        REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 0 );
                        outstation.postSPDU(master.getSPDU());
				        REQUIRE( outstation.getStatistic(Statistics::unexpected_messages__) == 1 );
                    }
                }
            }
        }
    }
}
