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
#include "privatekey.hpp"
#include "publickey.hpp"
#include "distinguishedname.hpp"
#include "certificatesignrequest.hpp"

namespace DNP3SAv6 { namespace Details { 
    class ICertificateStore;
	class Certificate
	{
	public :
        struct Options
        {
            enum KeyScheme {
                  rsa_plus_ecdh
                , ecdsa_plus_ecdh
                , single_key
                };

            Options(
                  unsigned int certificate_ttl_days
                , std::string ecc_curve
                , std::string sha
                )
                : key_scheme_(single_key)
                , certificate_ttl_days_(certificate_ttl_days)
                , ecdsa_curve_(ecc_curve)
                , ecdh_curve_(ecc_curve)
                , sha_(sha)
            { /* no-op */ }
            Options(
                  unsigned int certificate_ttl_days
                , unsigned int rsa_bits
                , std::string ecdh_curve
                , std::string sha
                )
                : key_scheme_(rsa_plus_ecdh)
                , certificate_ttl_days_(certificate_ttl_days)
                , rsa_bits_(rsa_bits)
                , ecdh_curve_(ecdh_curve)
                , sha_(sha)
            { /* no-op */ }
            Options(
                  unsigned int certificate_ttl_days
                , std::string ecdsa_curve
                , std::string ecdh_curve
                , std::string sha
                )
                : key_scheme_(ecdsa_plus_ecdh)
                , certificate_ttl_days_(certificate_ttl_days)
                , ecdsa_curve_(ecdsa_curve)
                , ecdh_curve_(ecdh_curve)
                , sha_(sha)
            { /* no-op */ }

            KeyScheme key_scheme_;
            unsigned int certificate_ttl_days_;
            unsigned int rsa_bits_ = 0;
            std::string ecdsa_curve_;
            std::string ecdh_curve_;
            std::string sha_;
        };

		virtual ~Certificate();

        Certificate(Certificate const &other);
		Certificate(Certificate &&other);
		Certificate& operator=(Certificate const &other);
		Certificate& operator=(Certificate &&other);

        Certificate& swap(Certificate &other);

        static Options makeOptions(
              unsigned int certificate_ttl_days
            , std::string ecc_curve
            , std::string sha
            );
        static Options makeOptions(
              unsigned int certificate_ttl_days
            , unsigned int rsa_bits
            , std::string ecdh_curve
            , std::string sha
            );
        static Options makeOptions(
              unsigned int certificate_ttl_days
            , std::string ecdsa_curve
            , std::string ecdh_curve
            , std::string sha
            );
        static Certificate generate(std::string const &subject_distinguished_name, Options const &options);
        static Certificate load(std::string const &filename);
        static Certificate load(std::string const &filename, std::string const &passkey); // if a private key is there, load it using the passkey
        static Certificate decode(std::vector< unsigned char > const &serialized_certificate, ICertificateStore *store_to_verify_with);

        void store(std::string const &filename, bool include_human_readable = false) const;
        void store(std::string const &filename, std::string const &passkey, bool include_human_readable = false) const; // includes the private key in PKCS#12 format
        std::vector< unsigned char > encode() const;

        PublicKey getECDHPublicKey() const;
        PrivateKey getECDHPrivateKey() const;

        DistinguishedName getSubjectName() const;
        DistinguishedName getIssuerName() const;

        CertificateSignRequest getCertificateSignRequest() const;
        Certificate sign(CertificateSignRequest const &request, Options const &options) const;
        bool verify(Certificate const &signed_certificate) const;

	protected :

	private :
        struct X509Adapter;

        Certificate(
              X509 *x509
            , EVP_PKEY *signature_private_key
            , EVP_PKEY *ecdh_private_key
            );

        static Certificate generate(
              bool own
            , EVP_PKEY *signature_private_key
            , EVP_PKEY *subject_public_key
            , EVP_PKEY *ecdh_public_key
            , X509_NAME *subject_name
            , X509_NAME *issuer_name
            , Options const &options
            );
        static std::unique_ptr< ASN1_INTEGER, std::function< void(ASN1_INTEGER*) > > generateRandomSerial();
        static std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > generateECCPrivateKey(std::string const &curve);
        static std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > generateRSAPrivateKey(unsigned int bits);
        static std::unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > generateRequest(EVP_PKEY *private_signing_key, EVP_PKEY *private_ecdh_key, X509_NAME *subject_distinguished_name);
        static std::unique_ptr< X509_NAME, std::function< void(X509_NAME*) > > makeName(std::string const &subject_distinguished_name);
        static void setExpiryTimes(X509 *x509, unsigned int days);
        static void sign(X509 *x509, EVP_PKEY *private_key, std::string const &sha);
        static std::unique_ptr< BIO, std::function< void(BIO*) > > openFile(std::string const &filename, bool for_reading);
        static void outputCertificate(BIO *bio, X509 *x509);
        static void outputPrivateKey(BIO *bio, EVP_PKEY *key, std::vector< unsigned char > passkey);
        static void outputX509Info(BIO *bio, X509 *x509);
        static void addECDHPublicKey(X509Adapter *x509, EVP_PKEY *ecdh_public_key);

        X509 *x509_ = nullptr;
        EVP_PKEY *signature_private_key_ = nullptr;
        EVP_PKEY *signature_public_key_ = nullptr;
        EVP_PKEY *ecdh_private_key_ = nullptr;
        EVP_PKEY *ecdh_public_key_ = nullptr;
	};
}}

#endif
