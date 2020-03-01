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
#include <vector>

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
        static Certificate load(std::string const &filename);
        static Certificate load(std::string const &filename, std::string const &passkey); // if a private key is there, load it using the passkey
        static Certificate decode(std::vector< unsigned char > const &serialized_certificate);

        void store(std::string const &filename, bool include_human_readable = false) const;
        void store(std::string const &filename, std::string const &passkey, bool include_human_readable = false) const; // includes the private key in PKCS#12 format
        std::vector< unsigned char > encode() const;

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
        static std::unique_ptr< BIO, std::function< void(BIO*) > > openFile(std::string const &filename, bool for_reading);
        static void outputCertificate(BIO *bio, X509 *x509);
        static void outputPrivateKey(BIO *bio, EVP_PKEY *key, std::string const &passkey);
        static void outputX509Info(BIO *bio, X509 *x509);

        X509 *x509_ = nullptr;
        EVP_PKEY *private_key_ = nullptr;
	};
}}

#endif
