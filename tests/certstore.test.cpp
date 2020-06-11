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
#include "../details/certificatestore.hpp"
#include "../details/certificate.hpp"
#include <boost/filesystem.hpp>

using namespace std;
using namespace DNP3SAv6;
using DNP3SAv6::Details::Certificate;
using DNP3SAv6::Details::CertificateStore;
namespace fs = boost::filesystem;

TEST_CASE( "Try to create a certificate store", "[certstore]" ) {
    CertificateStore store;
}

TEST_CASE( "Add a certificate to a certificate store", "[certstore]" ) {
    CertificateStore store;
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    store.add(certificate);
    REQUIRE(store.count() == 1);
}

TEST_CASE( "Add a certificate to a certificate store and remove it", "[certstore]" ) {
    CertificateStore store;
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    store.add(certificate);
    REQUIRE(store.count() == 1);
    store.remove("/CN=Device name");
    REQUIRE(store.count() == 0);
}

TEST_CASE( "Add an RSA certificate to a certificate store and use it to verify another certificate", "[certstore]" ) {
    CertificateStore store;
    Certificate ca_certificate(Certificate::generate("/CN=MyCA", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    store.add(ca_certificate);
    REQUIRE(store.count() == 1);
    Certificate certificate(Certificate::generate("/CN=MyDevice", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    Certificate signed_certificate(ca_certificate.sign(certificate.getCertificateSignRequest(), Certificate::makeOptions(30, "prime256v1", "sha256")));
    REQUIRE(store.verify(signed_certificate));
}

TEST_CASE( "Add a one-key certificate to a certificate store and use it to verify another certificate", "[certstore]" ) {
    CertificateStore store;
    Certificate ca_certificate(Certificate::generate("/CN=MyCA", Certificate::makeOptions(30, "prime256v1", "sha256")));
    store.add(ca_certificate);
    REQUIRE(store.count() == 1);
    Certificate certificate(Certificate::generate("/CN=MyDevice", Certificate::makeOptions(30, "prime256v1", "sha256")));
    Certificate signed_certificate(ca_certificate.sign(certificate.getCertificateSignRequest(), Certificate::makeOptions(30, "prime256v1", "sha256")));
    REQUIRE(store.verify(signed_certificate));
}
