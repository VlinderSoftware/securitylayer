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
#include "../details/masteroutstationassociationname.hpp"

using namespace std;
using namespace boost::asio;
using namespace DNP3SAv6;

SCENARIO( "New Master starts MOA with new Outstation", "[enrollment]" ) {
    unsigned char const request_bytes[] = { 0xC9, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 }; // class 123 poll

	Details::MasterOutstationAssociationName moa_name("new_master", "new_outstation", 0);
	io_context ioc;
	Config default_config;
	default_config.master_outstation_association_name_ = moa_name;
	Tests::DeterministicRandomNumberGenerator rng;
    Tests::UpdateKeyStoreStub update_key_store;
	Tests::CertificateStoreStub certificate_store;

	vector< unsigned char > encoded_certificates(64);
	mutable_buffer encoded_certificate_buffer(&encoded_certificates[0], encoded_certificates.size());
	rng.generate(encoded_certificate_buffer);
	certificate_store.setEncodedCertificates(encoded_certificates);

	Master master(ioc, default_config, rng, update_key_store, certificate_store);
	Outstation outstation(ioc, default_config, rng, update_key_store, certificate_store);

	WHEN( "the Master sends an APDU" ) {
		master.postAPDU(const_buffer(request_bytes, sizeof(request_bytes)));
		THEN( "the master will expect an association response" ) {
			REQUIRE( master.getState() == SecurityLayer::wait_for_association_response__ );
		}
		THEN( "the master and sends an association request message" ) {
			auto spdu(master.getSPDU());
			unsigned char const expected[] = {
				  0xc0, 0x80, 0x40, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00
				};
			REQUIRE( spdu.size() == sizeof(expected) );
			REQUIRE( memcmp(expected, spdu.data(), spdu.size()) == 0 );

			WHEN( "The SPDU is passed to the Outstation" ) {
				outstation.postSPDU(spdu);
				spdu = outstation.getSPDU();
				THEN( "the outstation changes state" ) {
					REQUIRE( outstation.getState() == SecurityLayer::wait_for_session_key_change_request__ );
				}
				THEN( "it will return an AssociationResponse SPDU with an encoded certificate and a nonce" ) {
					unsigned char const expected[] = {
						  0xc0, 0x80, 0x40, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
						, 0x40, 0x00
						, 0x04, 0x00
						, 0xb6, 0xd9, 0xff, 0x24, 0xec, 0xb2, 0x2c, 0x40, 0x82, 0xff, 0xc0, 0x51, 0xc0, 0x39, 0x22, 0x2c
						, 0x7d, 0xd9, 0x72, 0xe8, 0x09, 0x43, 0x9c, 0x4d, 0x25, 0xa4, 0x6c, 0x96, 0x47, 0xa8, 0x07, 0x74
						, 0xbb, 0x21, 0x4a, 0xa6, 0xd1, 0xea, 0xc1, 0x43, 0xb9, 0x40, 0xf1, 0xdd, 0xda, 0x3e, 0x3a, 0xa2
						, 0xd3, 0x66, 0xc0, 0xf6, 0x7b, 0x92, 0xe2, 0x92, 0xaf, 0x95, 0xfa, 0x0b, 0x66, 0xd3, 0x79, 0x42
						, 0xb6, 0x77, 0x45, 0xb7 
						};
					REQUIRE( memcmp(expected, spdu.data(), sizeof(expected)) == 0 );
					REQUIRE( memcmp(expected + 14, encoded_certificates.data(), encoded_certificates.size()) == 0 );
				}
				WHEN( "The new SPDU is passed to the Master" ) {
					master.postSPDU(spdu);
				}
			}
		}
	}
}

SCENARIO( "Existing Master (with pre-existing Update Key) starts MOA with new Outstation (device replacement)", "[enrollment]" ) {
}

SCENARIO( "New Master starts MOA with existing Outstation (with pre-existing Update Key) (Master replacement)", "[enrollment]" ) {
}
