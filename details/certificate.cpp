//!!! Some error checking is missing in this code!

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
#include "certificate.hpp"
#include <new>
#include <memory>
#include <stdexcept>
#include "../exceptions/contract.hpp"
#include "distinguishednameparser.hpp"
#include <openssl/pem.h>

using namespace std;

namespace DNP3SAv6 { namespace Details { 
/*static */Certificate Certificate::generate(
      string const &subject_distinguished_name
    , unsigned int ttl_days
    , string const &curve
    , string const &sha
    )
{
    auto x509_deleter([](X509 *v){ X509_free(v); });
    unique_ptr< X509, decltype(x509_deleter) > x509(X509_new(), x509_deleter);
    if (!x509.get()) throw bad_alloc();
    
    auto serial_number(generateRandomSerial());
    if (!X509_set_serialNumber(x509.get(), serial_number.get()))
    {
        throw runtime_error("Failed to set certificate serial number");
    }
    else
    { /* no-op */ }
    auto private_key(generatePrivateKey(curve));
    // generate the req (see openssl/apps/req.c lines 757 and further)
    auto request(generateRequest(private_key.get(), subject_distinguished_name));
    // fill out the x509 (see openssl/apps/x509.c lines 640 and further)
    if (!X509_set_issuer_name(x509.get(), X509_REQ_get_subject_name(request.get())))
    {
        throw runtime_error("Failed to set issuer name");
    }
    else
    { /* all is well */ }
    setExpiryTimes(x509.get(), ttl_days);
    if (!X509_set_subject_name(x509.get(), X509_REQ_get_subject_name(request.get())))
    {
        throw runtime_error("Failed to set the subject name");
    }
    else
    { /* all is well */ }
    auto pubkey(X509_REQ_get0_pubkey(request.get()));
    if (!pubkey || !X509_set_pubkey(x509.get(), pubkey))
    {
        throw runtime_error("Failed to set public key");
    }
    else
    { /* all is well */ }

    // sign it all with our own private key
    sign(x509.get(), private_key.get(), sha);

    return Certificate(x509.release(), private_key.release());
}

/*static */Certificate Certificate::load(std::string const& filename)
{
    auto bio(openFile(filename, true));
    X509 *x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    return Certificate(x509, nullptr);
}

/*static */Certificate Certificate::load(std::string const& filename, std::string const& passkey)
{
    auto bio(openFile(filename, true));
    X509 *x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    EVP_PKEY *privkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast< void* >(reinterpret_cast< void const * >(passkey.c_str()))));
    return Certificate(x509, privkey);
}

/*static */Certificate Certificate::decode(std::vector< unsigned char > const& serialized_certificate)
{
    unsigned char const *p(&serialized_certificate[0]);
    X509 *x509(d2i_X509(nullptr, &p, serialized_certificate.size()));
    return Certificate(x509, nullptr);
}

void Certificate::store(std::string const& filename, bool include_human_readable/* = false*/) const
{
    pre_condition(x509_);
    auto bio(openFile(filename, false));
    outputCertificate(bio.get(), x509_);
    if (include_human_readable) outputX509Info(bio.get(), x509_);
}

void Certificate::store(std::string const& filename, std::string const& passkey, bool include_human_readable/* = false*/) const
{
    pre_condition(x509_);
    pre_condition(private_key_);
    auto bio(openFile(filename, false));
    outputCertificate(bio.get(), x509_);
    outputPrivateKey(bio.get(), private_key_, passkey);
    if (include_human_readable) outputX509Info(bio.get(), x509_);
}

std::vector< unsigned char > Certificate::encode() const
{
    int required(i2d_X509(x509_, nullptr));
    if (required <= 0)
    {
        throw runtime_error("cannot encode certificate");
    }
    else
    { /* all is well */ }

    vector< unsigned char > retval(required);
    unsigned char *p(&retval[0]);
    int result(i2d_X509(x509_, &p));
    if (result != required)
    {
        throw runtime_error("failed to encode certificate");
    }
    else
    { /* all is well */ }

    return retval;
}

Certificate::Certificate(X509 *x509, EVP_PKEY *private_key)
    : x509_(x509)
    , private_key_(private_key)
{ /* no-op */ }

/*virtual */Certificate::~Certificate()
{
    EVP_PKEY_free(private_key_);
    X509_free(x509_);
}

/*static */unique_ptr< ASN1_INTEGER, std::function< void(ASN1_INTEGER*) > > Certificate::generateRandomSerial()
{
    auto asn1_integer_deleter([](ASN1_INTEGER *v){ ASN1_INTEGER_free(v); });
    unique_ptr< ASN1_INTEGER, decltype(asn1_integer_deleter) > serial_number(ASN1_INTEGER_new(), asn1_integer_deleter);

    auto bignum_deleter([](BIGNUM *b){ BN_free(b); });
    unique_ptr< BIGNUM, decltype(bignum_deleter) > bn_temp(BN_new(), bignum_deleter);
    if (!bn_temp.get()) throw bad_alloc();

    if (!BN_pseudo_rand(bn_temp.get(), 64/*bits in a serial number*/, 0, 0))
    {
        throw runtime_error("Failed to generate random serial number");//CertificateGenerationError();
    }
    else
    { /* all is well */ }
    if (!BN_to_ASN1_INTEGER(bn_temp.get(), serial_number.get()))
    {
        throw runtime_error("Failed to convert bignum to ASN1 integer");
    }
    else
    { /* all is well */ }

    return serial_number;
}
/*static */unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > Certificate::generatePrivateKey(string const &curve)
{
    int ecc_group(OBJ_txt2nid(curve.c_str()));
    auto ec_key_deleter([](EC_KEY *k){ EC_KEY_free(k); });
    unique_ptr< EC_KEY, decltype(ec_key_deleter) > ecc(EC_KEY_new_by_curve_name(ecc_group), ec_key_deleter);
    EC_KEY_set_asn1_flag(ecc.get(), OPENSSL_EC_NAMED_CURVE); // needed to sign with
    if (!EC_KEY_generate_key(ecc.get()))
    {
        throw runtime_error("Failed to generate ECC key");
    }
    else
    { /* all is well */ }
    auto evp_pkey_deleter([](EVP_PKEY *k){ EVP_PKEY_free(k); });
    unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(EVP_PKEY_new(), evp_pkey_deleter);
    if (!EVP_PKEY_assign_EC_KEY(pkey.get(), ecc.get()))
    {
        throw runtime_error("Failed to assign key to pkey");
    }
    else
    { /* all is well */ }
    ecc.release();

    return pkey;
}
/*static */unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > Certificate::generateRequest(EVP_PKEY *private_key, string const &subject_distinguished_name)
{
    auto x509_req_deleter([](X509_REQ *req){ X509_REQ_free(req); });
    unique_ptr< X509_REQ, decltype(x509_req_deleter) > req(X509_REQ_new(), x509_req_deleter);

    // we will be using version 1 certificates. The parameter to X509_REQ_set_version is "one less than the version", so we need to set 0
    if (!X509_REQ_set_version(req.get(), 0/* version 1 */))
    {
        throw runtime_error("Failed to set the X509 certificate request version");
    }
    else
    { /* all is well */ }
    setSubject(req.get(), subject_distinguished_name);
    if (!X509_REQ_set_pubkey(req.get(), private_key))
    {
        throw runtime_error("Failed to set the X509 certificate public key");
    }
    else
    { /* all is well */ }

    return req;
}

/*static */void Certificate::setSubject(X509_REQ *req, std::string const &subject_distinguished_name)
{
    auto parse_result(parse(subject_distinguished_name));
    if (!parse_result.second)
    {
        throw runtime_error("Failed to parse the distinguished name");
    }
    else
    { /* all is well */ }
    auto x509_name_deleter([](X509_NAME *name){ X509_NAME_free(name); });
    unique_ptr< X509_NAME, decltype(x509_name_deleter) > name(X509_NAME_new(), x509_name_deleter);
    for (auto entry : parse_result.first.elements_)
    {
        if (
              !X509_NAME_add_entry_by_txt(
                  name.get()
                , entry.type_.c_str()
                , MBSTRING_ASC
                , reinterpret_cast< unsigned char const * >(entry.value_.c_str())
                , entry.value_.size()
                , -1
                , 0
                )
            )
        {
            throw runtime_error("Failed to build name");
        }
        else
        { /* all is well */ }
    }
    if (!X509_REQ_set_subject_name(req, name.get()))
    {
        throw runtime_error("Failed to set subject name");
    }
    else
    { /* all is well */ }
}
/*static */void Certificate::setExpiryTimes(X509 *x509, unsigned int days)
{
    if (!X509_gmtime_adj(X509_getm_notBefore(x509), 0))
    {
        throw runtime_error("Failed to set expiry date");
    }
    else
    { /* all is well */ }
    if (!X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, nullptr))
    {
        throw runtime_error("Failed to set expiry date");
    }
    else
    { /* all is well */ }
}
/*static */void Certificate::sign(X509 *x509, EVP_PKEY *private_key, std::string const &sha)
{
    EVP_MD const *md(EVP_get_digestbyname(sha.c_str()));
    if (!md)
    {
        throw runtime_error("Unknown SHA");
    }
    else
    { /* all is well */ }
    auto evp_md_ctx_deleter([](EVP_MD_CTX *ctx){ EVP_MD_CTX_free(ctx); });
    unique_ptr< EVP_MD_CTX, decltype(evp_md_ctx_deleter) > md_context(EVP_MD_CTX_new(), evp_md_ctx_deleter);
    int default_nid;
    switch (EVP_PKEY_get_default_digest_nid(private_key, &default_nid))
    {
    case 2 : // the default digest is required: ignore the parameter given to us and use it in stead
        if (default_nid == NID_undef)
        {
            md = nullptr;
        }
        else
        {
            md = EVP_get_digestbynid(default_nid);
        }
        break;
    case 1 : // default digest is a suggestion - ignore it
        break;
    case -2 :
        throw runtime_error("Algorithm doesn't support signing");
    default :
        throw runtime_error("Failed to get default digest for algorithm");
    }
    EVP_PKEY_CTX *pk_context(nullptr);
    if (EVP_DigestSignInit(md_context.get(), &pk_context, md, nullptr, private_key) != 1)
    {
        throw runtime_error("Failed to initialize digest");
    }
    else
    { /* all is well */ }

    if (X509_sign_ctx(x509, md_context.get()) <= 0)
    {
        throw runtime_error("Failed to sign certificate");
    }
    else
    { /* all is well */ }
}
/*static */unique_ptr< BIO, function< void(BIO*) > > Certificate::openFile(std::string const &filename, bool for_reading)
{
    auto bio_deleter([](BIO *bio){ BIO_free_all(bio); });
    if (filename == "-") // stdin/stdout, depending on read_only bit
    {
        if (for_reading)
        {
            return unique_ptr< BIO, decltype(bio_deleter) >(BIO_new_fp(stdin, BIO_NOCLOSE), bio_deleter);
        }
        else
        {
            return unique_ptr< BIO, decltype(bio_deleter) >(BIO_new_fp(stdout, BIO_NOCLOSE), bio_deleter);
        }
    }
    else
    {
        return unique_ptr< BIO, decltype(bio_deleter) >(BIO_new_file(filename.c_str(), for_reading ? "rb" : "wb"), bio_deleter);
    }
}

/*static */void Certificate::outputCertificate(BIO *bio, X509 *x509)
{
    PEM_write_bio_X509(bio, x509);
}

void Certificate::outputPrivateKey(BIO *bio, EVP_PKEY *key, std::string const &passkey)
{
    vector< unsigned char > enc_passkey(passkey.begin(), passkey.end());
    PEM_write_bio_PrivateKey(bio, key, EVP_aes_256_cbc(), &enc_passkey[0], enc_passkey.size(), nullptr, nullptr);
}

/*static */void Certificate::outputX509Info(BIO *bio, X509 *x509)
{
    if(!X509_print_ex(bio, x509, 0, 0))
    {
        throw runtime_error("Error writing certificate to file");
    }
    else
    { /* all is well */ }
}
}}
