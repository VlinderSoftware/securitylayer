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
#ifndef dnp3sav6_details_certificate_hpp
#define dnp3sav6_details_certificate_hpp

#include <openssl/x509.h>
#include <functional>
#include <memory>
#include <string>

namespace DNP3SAv6 { namespace Details { 
	class Certificate
	{
	public :
		virtual ~Certificate();

        static Certificate generate(
              std::string const &subject_distinguished_name
            , unsigned int ttl_days
            , std::string const &curve
            , std::string const &sha
            );

		Certificate(Certificate const&) = delete;
		Certificate(Certificate &&) = default;
		Certificate& operator=(Certificate const&) = delete;
		Certificate& operator=(Certificate &&) = default;

	protected :

	private :
        Certificate(X509 *x509, EVP_PKEY *private_key);

        static std::unique_ptr< ASN1_INTEGER, std::function< void(ASN1_INTEGER*) > > generateRandomSerial();
        static std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > generatePrivateKey(std::string const &curve);
        static std::unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > generateRequest(EVP_PKEY *private_key, std::string const &subject_distinguished_name);
        static void setSubject(X509_REQ *req, std::string const &subject_distinguished_name);
        static void setExpiryTimes(X509 *x509, unsigned int days);
        static void sign(X509 *x509, EVP_PKEY *private_key, std::string const &sha);

        X509 *x509_ = nullptr;
        EVP_PKEY *private_key_ = nullptr;
	};
}}

#endif
