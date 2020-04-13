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
#include "../details/certificate.hpp"

using namespace std;
using namespace DNP3SAv6;
using DNP3SAv6::Details::Certificate;

TEST_CASE( "Try to create a one-key instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
}

TEST_CASE( "Try to create an RSA + ECDH instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
}

TEST_CASE( "Try to create an ECDSA + ECDH instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
}
