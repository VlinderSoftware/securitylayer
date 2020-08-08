/* Copyright 2020  Ronald Landheer-Cieslak
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
#ifndef dnp3sav6_tests_certificatestorestub_hpp
#define dnp3sav6_tests_certificatestorestub_hpp

#include "../details/icertificatestore.hpp"

namespace DNP3SAv6 {
namespace Details {
	class Certificate;
	struct DistinguishedName;
}
namespace Tests {
class CertificateStoreStub : public Details::ICertificateStore
{
public :
	CertificateStoreStub() = default;
	virtual ~CertificateStoreStub() = default;

	CertificateStoreStub(CertificateStoreStub const&) = delete;
	CertificateStoreStub& operator=(CertificateStoreStub const&) = delete;
	CertificateStoreStub(CertificateStoreStub&&) = default;
	CertificateStoreStub& operator=(CertificateStoreStub&&) = default;

    /*virtual */size_t count() const/* = 0*/;
    /*virtual */void add(Details::Certificate const &certificate)/* = 0*/;
    /*virtual */void remove(Details::DistinguishedName const &name)/* = 0*/;
    /*virtual */bool verify(Details::Certificate const &certificate) const/* = 0*/;

	/*virtual */boost::asio::const_buffer encode(Details::DistinguishedName const &certificate_name, bool encode_chain) const/* = 0*/;
	/*virtual */void decode(boost::asio::const_buffer const &encoded_certs, VerificationPolicy verification_policy) override/* = 0*/;

	void setEncodedCertificates(std::vector< unsigned char > const &encoded_certificates);

private :
	std::vector< unsigned char > encoded_certificates_;
};
}}

#endif


