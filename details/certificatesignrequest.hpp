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
#ifndef dnp3sav6_details_certificatesignrequest_hpp
#define dnp3sav6_details_certificatesignrequest_hpp

#include <openssl/x509.h>
#include <memory>
#include <functional>
#include "ecdhpublickey.hpp"

namespace DNP3SAv6 { namespace Details { 
	class CertificateSignRequest
	{
	public :
        ~CertificateSignRequest();
        CertificateSignRequest(CertificateSignRequest const &) = default;
        CertificateSignRequest(CertificateSignRequest &&) = default;
        CertificateSignRequest& operator=(CertificateSignRequest const &) = default;
        CertificateSignRequest& operator=(CertificateSignRequest &&) = default;

        EVP_PKEY* getSubjectPublicKey() const;
        std::unique_ptr< EC_KEY, std::function< void(EC_KEY*) > > getECDHPublicKey() const;
        X509_NAME* getSubjectName() const;

    private :
        CertificateSignRequest(std::unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > &&req);

        X509_REQ *req_ = nullptr;

        friend class Certificate;
	};
}}

#endif
