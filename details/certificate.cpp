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
#include <cstring>
#include "../exceptions/contract.hpp"
#include "distinguishednameparser.hpp"
#include "pbkdf2.hpp"
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include "icertificatestore.hpp"
#include "constants.hpp"
#include "ecdhpublickey.hpp"

using namespace std;

namespace {
    int passkeyCallback__(char *buf, int size, int rwflag, void *u)
    {
        vector< unsigned char > *key(static_cast< vector< unsigned char >* >(u));
        if ((unsigned int)size < key->size())
        {
            throw runtime_error("key too large");
        }
        else
        { /* we have enough space */ }
        copy(key->begin(), key->end(), buf);
        return key->size();
    }
}

namespace DNP3SAv6 { namespace Details { 
struct Certificate::X509Adapter
{
    X509Adapter(X509 *x509)
        : x509_(x509)
    { /* no-op */ }

    X509Adapter(X509_REQ *req)
        : req_(req)
    { /* no-op */ }

    void addExtensions(STACK_OF(X509_EXTENSION) *extensions)
    {
        if (x509_)
        {
            for (int i(0); i < sk_X509_EXTENSION_num(extensions); ++i)
            {
                if (!X509_add_ext(x509_, sk_X509_EXTENSION_value(extensions, i), -1))
                {
                    throw runtime_error("failed to add extension to certificate");
                }
                else
                { /* all is well */ }
            }
        }
        else
        { /* no-op */ }
        if (req_)
        {
            if (!X509_REQ_add_extensions(req_, extensions))
            {
                throw runtime_error("failed to add extension to certificate request");
            }
            else
            { /* all is well */ }
        }
        else
        { /* no-op */ }
    }

    X509 *x509_ = nullptr;
    X509_REQ *req_ = nullptr;
};

/*static */Certificate::Options Certificate::makeOptions(
      unsigned int certificate_ttl_days
    , std::string ecc_curve
    , std::string sha
    )
{
    return Options(certificate_ttl_days, ecc_curve, sha);
}
/*static */Certificate::Options Certificate::makeOptions(
      unsigned int certificate_ttl_days
    , unsigned int rsa_bits
    , std::string ecdh_curve
    , std::string sha
    )
{
    return Options(certificate_ttl_days, rsa_bits, ecdh_curve, sha);
}
/*static */Certificate::Options Certificate::makeOptions(
      unsigned int certificate_ttl_days
    , std::string ecdsa_curve
    , std::string ecdh_curve
    , std::string sha
    )
{
    return Options(certificate_ttl_days, ecdsa_curve, ecdh_curve, sha);
}

/*static */Certificate Certificate::generate(string const &subject_distinguished_name, Options const &options)
{
    auto rsa_private_key(options.rsa_bits_ ? generateRSAPrivateKey(options.rsa_bits_) : decltype(generateRSAPrivateKey(options.rsa_bits_))());
    auto ecdsa_private_key(generateECCPrivateKey(options.ecdsa_curve_));
    auto ecdh_private_key((options.key_scheme_ != Options::single_key) ? generateECCPrivateKey(options.ecdh_curve_) : decltype(generateECCPrivateKey(options.ecdh_curve_))());
    auto name(makeName(subject_distinguished_name));

    Certificate retval(generate(
          true
        , options.rsa_bits_ ? rsa_private_key.get() : ecdsa_private_key.get()
        , options.rsa_bits_ ? rsa_private_key.get() : ecdsa_private_key.get()
        , ecdh_private_key.get()
        , name.get()
        , name.get()
        , options
        ));
    rsa_private_key.release();
    ecdsa_private_key.release();
    ecdh_private_key.release();
    return retval;
}

/*static */Certificate Certificate::load(std::string const &filename)
{
    auto bio(openFile(filename, true));
    if (!bio) throw runtime_error("failed to open file");
    X509 *x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!x509) throw runtime_error("failed to read file");
    return Certificate(x509, nullptr, nullptr);
}

/*static */Certificate Certificate::load(std::string const &filename, std::string const &passkey)
{
    auto bio(openFile(filename, true));
    if (!bio) throw runtime_error("failed to open file");
    X509 *x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!x509) throw runtime_error("failed to read file");

    PBKDF2 salt_kdf(passkey);
    auto signature_salt(salt_kdf(16));
    auto ecdh_salt(salt_kdf(16));
    PBKDF2 signature_kdf(passkey, signature_salt);
    auto signature_passkey(signature_kdf(32));
    PBKDF2 ecdh_kdf(passkey, ecdh_salt);
    auto ecdh_passkey(ecdh_kdf(32));

    EVP_PKEY *signature_privkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, passkeyCallback__, &signature_passkey));
    if (!signature_privkey) throw runtime_error("failed to read private key");
    EVP_PKEY *ecdh_privkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, passkeyCallback__, &ecdh_passkey)); // allowed to fail

    return Certificate(x509, signature_privkey, ecdh_privkey);
}

/*static */Certificate Certificate::decode(std::vector< unsigned char > const &serialized_certificate, ICertificateStore *store_to_verify_with)
{
    unsigned char const *p(&serialized_certificate[0]);
    X509 *x509(d2i_X509(nullptr, &p, serialized_certificate.size()));
    if (x509) throw runtime_error("failed to read file");
    Certificate retval(x509, nullptr, nullptr);
    if (!store_to_verify_with || store_to_verify_with->verify(retval))
    {
        return retval;
    }
    else
    {
        throw runtime_error("Certificate verification failed");
    }
}

void Certificate::store(std::string const &filename, bool include_human_readable/* = false*/) const
{
    pre_condition(x509_);
    auto bio(openFile(filename, false));
    if (!bio) throw runtime_error("failed to open file");
    outputCertificate(bio.get(), x509_);
    if (include_human_readable) outputX509Info(bio.get(), x509_);
}

void Certificate::store(std::string const &filename, std::string const &passkey, bool include_human_readable/* = false*/) const
{
    pre_condition(x509_);
    pre_condition(signature_private_key_);
    auto bio(openFile(filename, false));
    if (!bio) throw runtime_error("failed to open file");

    PBKDF2 salt_kdf(passkey);
    auto signature_salt(salt_kdf(16));
    auto ecdh_salt(salt_kdf(16));
    PBKDF2 signature_kdf(passkey, signature_salt);
    auto signature_passkey(signature_kdf(32));
    PBKDF2 ecdh_kdf(passkey, ecdh_salt);
    auto ecdh_passkey(ecdh_kdf(32));

    outputCertificate(bio.get(), x509_);
    outputPrivateKey(bio.get(), signature_private_key_, signature_passkey);
    if (ecdh_private_key_)
    {
        outputPrivateKey(bio.get(), ecdh_private_key_, ecdh_passkey);
    }
    else
    { /* no ECDH private key */ }
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

PublicKey Certificate::getECDHPublicKey() const
{
    invariant(ecdh_public_key_);
    EVP_PKEY_up_ref(ecdh_public_key_);
    return PublicKey(ecdh_public_key_);
}

PrivateKey Certificate::getECDHPrivateKey() const
{
    return PrivateKey();
}

namespace {
    DistinguishedName X509_NAME_to_DistinguishedName(X509_NAME *name)
    {
        DistinguishedName retval;

        for (int entry_location(0); entry_location < X509_NAME_entry_count(name); ++entry_location)
        {
            auto entry(X509_NAME_get_entry(name, entry_location));
            auto type(X509_NAME_ENTRY_get_object(entry));
            auto short_name(OBJ_nid2sn(OBJ_obj2nid(type)));
            auto data(X509_NAME_ENTRY_get_data(entry));
            DistinguishedName::Element element(string(short_name), string((char*)ASN1_STRING_get0_data(data), ASN1_STRING_length(data)));
            retval.elements_.push_back(element);
        }
    
        return retval;
    }
}

DistinguishedName Certificate::getSubjectName() const
{
    auto name(X509_get_subject_name(x509_));
    return X509_NAME_to_DistinguishedName(name);
}
DistinguishedName Certificate::getIssuerName() const
{
    auto name(X509_get_issuer_name(x509_));
    return X509_NAME_to_DistinguishedName(name);
}

CertificateSignRequest Certificate::getCertificateSignRequest() const
{
    return CertificateSignRequest(generateRequest(signature_private_key_, ecdh_private_key_, X509_get_subject_name(x509_)));
}

Certificate Certificate::sign(CertificateSignRequest const& request, Options const &options) const
{
    auto evp_pkey_deleter([](EVP_PKEY *key){ EVP_PKEY_free(key); });
    unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > temp_evp_pkey(EVP_PKEY_new(), evp_pkey_deleter);
    if (!temp_evp_pkey)
    {
        throw bad_alloc();
    }
    else
    { /* all is well */ }
    EVP_PKEY_set1_EC_KEY(temp_evp_pkey.get(), request.getECDHPublicKey().get());

    return generate(
          false
        , signature_private_key_
        , request.getSubjectPublicKey()
        , request.getECDHPublicKey().get() ? temp_evp_pkey.get() : nullptr
        , request.getSubjectName()
        , X509_get_subject_name(x509_)
        , options
        );
}

bool Certificate::verify(Certificate const& signed_certificate) const
{
    return (X509_verify(signed_certificate.x509_, signature_public_key_) == 1);
}

Certificate::Certificate(X509 *x509, EVP_PKEY *signature_private_key, EVP_PKEY *ecdh_private_key)
    : x509_(x509)
    , signature_private_key_(signature_private_key)
    , signature_public_key_(signature_private_key_ ? signature_private_key_ : X509_get0_pubkey(x509_))
    , ecdh_private_key_(ecdh_private_key)
{
    pre_condition(x509);
    auto evp_pkey_deleter([](EVP_PKEY *key){ EVP_PKEY_free(key); });
    unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > ecdh_public_key(nullptr, evp_pkey_deleter);
    if (ecdh_private_key)
    {
        ecdh_public_key_ = ecdh_private_key;
    }
    else
    {
        //TODO at this point, we may be dealing withan X509 certificate that has our extension, or its public key may be an ECC key we use for both ECDH and its signature.
        // see if it has our extension
        auto extensions(X509_get0_extensions(x509));
        if (extensions)
        {
            for (unsigned int i(0); i < (unsigned int)sk_X509_EXTENSION_num(extensions); ++i)
            {
                auto asn1_object_deleter([](ASN1_OBJECT *obj){ ASN1_OBJECT_free(obj); });
                unique_ptr< ASN1_OBJECT, decltype(asn1_object_deleter) > expected_oid(OBJ_txt2obj(DNP3_ECDH_EXTENSION_OID, 1), asn1_object_deleter);
                if (!expected_oid) throw bad_alloc();

                auto extension(sk_X509_EXTENSION_value(extensions, i));
                auto critical(X509_EXTENSION_get_critical(extension));
                auto oid(X509_EXTENSION_get_object(extension));
                auto data(X509_EXTENSION_get_data(extension));
                if (OBJ_cmp(expected_oid.get(), oid) == 0)
                {
                    unsigned char const *beg(ASN1_STRING_get0_data(data));
                    auto ecdh_public_key_deleter([](ECDHPublicKey *pubkey){ ECDHPublicKey_free(pubkey); });
                    unique_ptr< ECDHPublicKey, decltype(ecdh_public_key_deleter) > public_key(d2i_ECDHPublicKey(nullptr, &beg, ASN1_STRING_length(data)), ecdh_public_key_deleter);
                    if (!public_key || !public_key->algorithm || !public_key->algorithm->algorithm || !public_key->publicKey)
                    {
                        throw runtime_error("Error decoding the ECDH public key");
                    }
                    else
                    { /* all is well */ }
                    /* If we have curve parameters, we should use them regardless of the algorithm OID. We are required 
                     * to check whether the parameters correspond to the ones used according to the implementation we use 
                     * for the curve: they should. If they don't, we need to bail out now.
                     * That is all well and good, but OpenSSL's EC_GROUP_cmd has been broken since version 1.0.2a:
                     * creating a curve from the NID vs. creating it from the parameters, while it renders the same 
                     * curve functionally, does not give two equal curves for which EC_GROUOP_cmd consistently 
                     * returns equality. We will therefore obey OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
                     * to avoid running into trouble at run-time with well-defined curves. Worst cse, the 
                     * ECDH fails later. */
                    int curve_nid(OBJ_obj2nid(public_key->algorithm->algorithm));
                    auto ec_group_deleter([](EC_GROUP *key){ EC_GROUP_free(key); });
                    unique_ptr< EC_GROUP, decltype(ec_group_deleter) > ec_group(nullptr, ec_group_deleter);

                    if (public_key->algorithm->parameters)
                    {
                        ec_group.reset(EC_GROUP_new_from_ecparameters(public_key->algorithm->parameters));
                        if (!ec_group)
                        {
                            throw runtime_error("failed to parse curve parameters");
                        }
                        else
                        { /* all is well */ }
                    }
                    else
                    { /* no parameters provided */ }
                    if (curve_nid == NID_undef)
                    {
                        if (!ec_group)
                        {
                            throw runtime_error("Unsupported EC curve and no parameters provided");
                        }
                        else
                        { /* OK, can't check the thing though - warning maybe? */ }
                    }
                    else
                    {
                        if (ec_group)
                        {
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
                            decltype(ec_group) ec_group_tmp(EC_GROUP_new_by_curve_name(curve_nid), ec_group_deleter);
                            if (EC_GROUP_cmp(ec_group.get(), ec_group_tmp.get(), nullptr) != 0)
                            {
                                throw runtime_error("Mismatched curve parameters");
                            }
                            else
                            { /* all is well */ }
#endif
                        }
                        else
                        {
                            ec_group.reset(EC_GROUP_new_by_curve_name(curve_nid));
                            if (!ec_group)
                            {
                                throw runtime_error("Curve not supported and no parameters provided");
                            }
                            else
                            { /* all is well */ }
                        }
                    }
                    auto ec_point_deleter([](EC_POINT *ec_point){ EC_POINT_free(ec_point); });
                    unique_ptr< EC_POINT, decltype(ec_point_deleter) > ec_point(EC_POINT_new(ec_group.get()), ec_point_deleter);
                    if (!ec_point)
                    {
                        throw runtime_error("Failed to allocate public key");
                    }
                    else
                    { /* all is well */ }
                    if (!EC_POINT_oct2point(ec_group.get(), ec_point.get(), ASN1_STRING_get0_data(public_key->publicKey), ASN1_STRING_length(public_key->publicKey), nullptr))
                    {
                        throw runtime_error("Failed to decode public key");
                    }
                    else
                    { /* all is well */ }

                    auto ec_key_deleter([](EC_KEY *key){ EC_KEY_free(key); });
                    unique_ptr< EC_KEY, decltype(ec_key_deleter) > ec_key(EC_KEY_new(), ec_key_deleter);
                    if (!EC_KEY_set_group(ec_key.get(), ec_group.get()))
                    {
                        throw runtime_error("Failed to set key group (curve)");
                    }
                    else
                    { /* all is well */ }
                    if (!EC_KEY_set_public_key(ec_key.get(), ec_point.get()))
                    {
                        throw runtime_error("failed to set public key");
                    }
                    else
                    { /* all is well */ }
                    ecdh_public_key.reset(EVP_PKEY_new());
                    if (!ecdh_public_key)
                    {
                        throw bad_alloc();
                    }
                    else
                    { /* all is well */ }
                    if (!EVP_PKEY_set1_EC_KEY(ecdh_public_key.get(), ec_key.get()))
                    {
                        throw runtime_error("failed to set public key");
                    }
                    else
                    { /* no-op */ }
                }
                else
                { /* this is not the OID you're looking for */ }
            }
        }
        else
        { /* no extensions */ }
        if (!ecdh_public_key_ && !ecdh_public_key)
        {
            ecdh_public_key_ = X509_get0_pubkey(x509);
            //TODO check that it's really an ECDH public key. Otherwise, throw an exception
        }
        else
        { /* already have our public key */ }

        if (!ecdh_public_key_) ecdh_public_key_ = ecdh_public_key.release();
    }
}

/*virtual */Certificate::~Certificate()
{
    if (ecdh_private_key_ != signature_private_key_) // may be the same if we use a single key
    {
        EVP_PKEY_free(ecdh_private_key_);
    }
    else
    { /* not the same key */ }
    EVP_PKEY_free(signature_private_key_);
    X509_free(x509_);
}
Certificate::Certificate(Certificate const& other)
    : x509_(other.x509_)
    , signature_private_key_(other.signature_private_key_)
    , signature_public_key_(other.signature_public_key_)
    , ecdh_private_key_(other.ecdh_private_key_)
    , ecdh_public_key_(other.ecdh_public_key_)
{
    if (x509_) X509_up_ref(x509_);
    if (ecdh_private_key_ && (ecdh_private_key_ != signature_private_key_)) EVP_PKEY_up_ref(ecdh_private_key_);
    if (signature_private_key_) EVP_PKEY_up_ref(signature_private_key_);
}
Certificate::Certificate(Certificate &&other)
    : x509_(other.x509_)
    , signature_private_key_(other.signature_private_key_)
    , signature_public_key_(other.signature_public_key_)
    , ecdh_private_key_(other.ecdh_private_key_)
    , ecdh_public_key_(other.ecdh_public_key_)
{
    other.x509_ = nullptr;
    other.signature_private_key_ = nullptr;
    other.ecdh_private_key_ = nullptr;
}
Certificate& Certificate::operator=(Certificate const &other)
{
    Certificate temp(other);
    return swap(temp);
}
Certificate& Certificate::operator=(Certificate &&other)
{
    Certificate temp(move(other));
    return swap(temp);
}

Certificate& Certificate::swap(Certificate &other)
{
    std::swap(x509_, other.x509_);
    std::swap(signature_private_key_, other.signature_private_key_);
    std::swap(ecdh_private_key_, other.ecdh_private_key_);

    return *this;
}

/*static */Certificate Certificate::generate(
      bool own
    , EVP_PKEY *signature_private_key
    , EVP_PKEY *subject_public_key
    , EVP_PKEY *ecdh_public_key
    , X509_NAME *subject_name
    , X509_NAME *issuer_name
    , Options const &options
    )
{
    auto x509_deleter([](X509 *v){ X509_free(v); });
    unique_ptr< X509, decltype(x509_deleter) > x509(X509_new(), x509_deleter);
    if (!x509) throw bad_alloc();

    // we will be using version 3 certificates. The parameter to X509_REQ_set_version is "one less than the version", so we need to set 2
    if (!X509_set_version(x509.get(), 2/* version 3 */))
    {
        throw runtime_error("Failed to set the X509 certificate version");
    }
    else
    { /* all is well */ }

    auto serial_number(generateRandomSerial());
    if (!X509_set_serialNumber(x509.get(), serial_number.get()))
    {
        throw runtime_error("Failed to set certificate serial number");
    }
    else
    { /* no-op */ }
    if (!X509_set_issuer_name(x509.get(), issuer_name))
    {
        throw runtime_error("Failed to set issuer name");
    }
    else
    { /* all is well */ }
    if (options.certificate_ttl_days_)
    {
        setExpiryTimes(x509.get(), options.certificate_ttl_days_);
    }
    else
    { /* never expires */ }
    if (!X509_set_subject_name(x509.get(), subject_name))
    {
        throw runtime_error("Failed to set the subject name");
    }
    else
    { /* all is well */ }
    if (!X509_set_pubkey(x509.get(), subject_public_key))
    {
        throw runtime_error("Failed to set public key");
    }
    else
    { /* all is well */ }

    if (ecdh_public_key)
    {
        X509Adapter adapter(x509.get());
        addECDHPublicKey(&adapter, ecdh_public_key);
    }
    else
    { /* nothing to put in an extension */ }

    // sign it all with our own private key
    sign(x509.get(), signature_private_key, options.sha_);

    Certificate retval(x509.get(), own ? signature_private_key : nullptr, own ? ecdh_public_key : nullptr);
    x509.release();
    return retval;
}

/*static */unique_ptr< ASN1_INTEGER, std::function< void(ASN1_INTEGER*) > > Certificate::generateRandomSerial()
{
    auto asn1_integer_deleter([](ASN1_INTEGER *v){ ASN1_INTEGER_free(v); });
    unique_ptr< ASN1_INTEGER, decltype(asn1_integer_deleter) > serial_number(ASN1_INTEGER_new(), asn1_integer_deleter);
    if (!serial_number.get()) throw std::bad_alloc();

    auto bignum_deleter([](BIGNUM *b){ BN_free(b); });
    unique_ptr< BIGNUM, decltype(bignum_deleter) > bn_temp(BN_new(), bignum_deleter);
    if (!bn_temp) throw bad_alloc();

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
/*static */unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > Certificate::generateECCPrivateKey(string const &curve)
{
    if (curve.empty()) return unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > >();
    pre_condition(RAND_status());
    int ecc_group(OBJ_txt2nid(curve.c_str()));
    auto ec_key_deleter([](EC_KEY *k){ EC_KEY_free(k); });
    unique_ptr< EC_KEY, decltype(ec_key_deleter) > ecc(EC_KEY_new_by_curve_name(ecc_group), ec_key_deleter);
    if (!ecc) throw std::bad_alloc();
    EC_KEY_set_asn1_flag(ecc.get(), OPENSSL_EC_NAMED_CURVE); // needed to sign with
    if (!EC_KEY_generate_key(ecc.get()))
    {
        throw runtime_error("Failed to generate ECC key");
    }
    else
    { /* all is well */ }
    auto evp_pkey_deleter([](EVP_PKEY *k){ EVP_PKEY_free(k); });
    unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(EVP_PKEY_new(), evp_pkey_deleter);
    if (!pkey) throw std::bad_alloc();
    if (!EVP_PKEY_assign_EC_KEY(pkey.get(), ecc.get()))
    {
        throw runtime_error("Failed to assign key to pkey");
    }
    else
    { /* all is well */ }
    ecc.release();

    return pkey;
}
static int BNGenCallback(int, int, BN_GENCB *)
{
    return 1;
}
/*static */unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > Certificate::generateRSAPrivateKey(unsigned int bits)
{
    pre_condition(RAND_status());
    auto rsa_deleter([](RSA *rsa){ RSA_free(rsa); });
    unique_ptr< RSA, decltype(rsa_deleter) > rsa(RSA_new(), rsa_deleter);
    if (!rsa) throw bad_alloc();
    auto bn_deleter([](BIGNUM *bn){ BN_free(bn); });
    unique_ptr< BIGNUM, decltype(bn_deleter) > exponent(BN_new(), bn_deleter);
    if (!exponent) throw bad_alloc();
    BN_set_word(exponent.get(), RSA_F4);
    auto bn_gencb_deleter([](BN_GENCB *cb){ BN_GENCB_free(cb); });
    unique_ptr< BN_GENCB, decltype(bn_gencb_deleter) > cb(BN_GENCB_new(), bn_gencb_deleter);
    if (!cb) throw bad_alloc();

    BN_GENCB_set(cb.get(), BNGenCallback, nullptr);

    unsigned int const primes(
          bits < 1024 ? 2
        : bits < 4096 ? 3
        : bits < 8192 ? 4
        : 5
        );

    if (1 != RSA_generate_multi_prime_key(rsa.get(), bits, primes, exponent.get(), cb.get())) throw runtime_error("Something more eloquent here");

    auto evp_pkey_deleter([](EVP_PKEY *k){ EVP_PKEY_free(k); });
    unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(EVP_PKEY_new(), evp_pkey_deleter);
    if (!pkey) throw std::bad_alloc();
    if (!EVP_PKEY_assign_RSA(pkey.get(), rsa.get()))
    {
        throw runtime_error("Failed to assign key to pkey");
    }
    else
    { /* all is well */ }
    rsa.release();

    return pkey;
}
/*static */unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > Certificate::generateRequest(EVP_PKEY *private_signing_key, EVP_PKEY *private_ecdh_key, X509_NAME *subject_distinguished_name)
{
    auto x509_req_deleter([](X509_REQ *req){ X509_REQ_free(req); });
    unique_ptr< X509_REQ, decltype(x509_req_deleter) > req(X509_REQ_new(), x509_req_deleter);
    if (!req) throw std::bad_alloc();

    // we will be using version 3 certificates. The parameter to X509_REQ_set_version is "one less than the version", so we need to set 2
    if (!X509_REQ_set_version(req.get(), 2/* version 3 */))
    {
        throw runtime_error("Failed to set the X509 certificate request version");
    }
    else
    { /* all is well */ }
    if (!X509_REQ_set_subject_name(req.get(), subject_distinguished_name))
    {
        throw runtime_error("Failed to set subject name");
    }
    else
    { /* all is well */ }
    if (!X509_REQ_set_pubkey(req.get(), private_signing_key))
    {
        throw runtime_error("Failed to set the X509 certificate public key");
    }
    else
    { /* all is well */ }
    if (private_ecdh_key)
    {
        X509Adapter adapter(req.get());
        addECDHPublicKey(&adapter, private_ecdh_key);
    }
    else
    { /* nothing to put in an extension */ }

    return req;
}

/*static */std::unique_ptr< X509_NAME, std::function< void(X509_NAME*) > > Certificate::makeName(std::string const &subject_distinguished_name)
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
    if (!name) throw std::bad_alloc();
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

    return name;
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
    if (!md_context) throw std::bad_alloc();
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

void Certificate::outputPrivateKey(BIO *bio, EVP_PKEY *key, std::vector< unsigned char > passkey)
{
    PEM_write_bio_PrivateKey(bio, key, EVP_aes_256_cbc(), &passkey[0], passkey.size(), nullptr, nullptr);
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

void Certificate::addECDHPublicKey(X509Adapter *x509, EVP_PKEY *ecdh_public_key)
{
    auto asn1_object_deleter([](ASN1_OBJECT *obj){ ASN1_OBJECT_free(obj); });
    unique_ptr< ASN1_OBJECT, decltype(asn1_object_deleter) > asn1(OBJ_txt2obj(DNP3_ECDH_EXTENSION_OID, 1), asn1_object_deleter);
    if (!asn1) throw bad_alloc();

    // get the ECC key out of the EVP key
    EC_KEY *ec_public_key(EVP_PKEY_get0_EC_KEY(ecdh_public_key));
    assert(ec_public_key);

    AlgorithmIdentifier algorithm;
    ECDHPublicKey pubkey_to_encode;
    pubkey_to_encode.algorithm = &algorithm;
    auto group(EC_KEY_get0_group(ec_public_key));
    algorithm.algorithm = OBJ_nid2obj(EC_GROUP_get_curve_name(group));
    algorithm.parameters = EC_GROUP_get_ecparameters(group, nullptr);

    // encode the public key into an octet string
    vector< unsigned char > encoded_public_key;
    {
        int required_size(i2o_ECPublicKey(ec_public_key, nullptr));
        if (required_size <= 0)
        {
            throw runtime_error("Failed to encode ECDH public key");
        }
        else
        { /* all is well */ }
        encoded_public_key.resize(required_size);
        unsigned char *out(&encoded_public_key[0]);
        int output_size(i2o_ECPublicKey(ec_public_key, &out));
        if (output_size != required_size)
        {
            throw runtime_error("Failed to encode ECDH public key");
        }
        else
        { /* all is well */ }
    }
    // combine the body of our object
    ASN1_BIT_STRING public_key_as_octet_string;
    memset(&public_key_as_octet_string, 0, sizeof(public_key_as_octet_string));
    public_key_as_octet_string.type = V_ASN1_OCTET_STRING;
    public_key_as_octet_string.length = encoded_public_key.size();
    public_key_as_octet_string.data = &encoded_public_key[0];
    pubkey_to_encode.publicKey = &public_key_as_octet_string;

    vector< unsigned char > der_encoded_extension_payload;
    {
        int required_size(i2d_ECDHPublicKey(&pubkey_to_encode, nullptr));
        if (required_size <= 0)
        {
            throw runtime_error("Failed to encode ECDH public key");
        }
        else
        { /* all is well */ }
        der_encoded_extension_payload.resize(required_size);
        unsigned char *out(&der_encoded_extension_payload[0]);
        int output_size(i2d_ECDHPublicKey(&pubkey_to_encode, &out));
        if (output_size != required_size)
        {
            throw runtime_error("Failed to encode ECDH public key");
        }
        else
        { /* all is well */ }
    }

    auto asn1_octet_string_deleter([](ASN1_OCTET_STRING * octet_string){ ASN1_OCTET_STRING_free(octet_string); });
    unique_ptr< ASN1_OCTET_STRING, decltype(asn1_octet_string_deleter) > envelope(ASN1_OCTET_STRING_new(), asn1_octet_string_deleter);
    if (!envelope) throw bad_alloc();
    ASN1_OCTET_STRING_set(envelope.get(), &der_encoded_extension_payload[0], der_encoded_extension_payload.size());

    auto x509_extension_deleter([](X509_EXTENSION *ext){ X509_EXTENSION_free(ext); });
    unique_ptr< X509_EXTENSION, decltype(x509_extension_deleter) > extension(X509_EXTENSION_create_by_OBJ(nullptr, asn1.get(), 0, envelope.get()), x509_extension_deleter);
    if (!extension) throw bad_alloc();

    auto stack_of_x509_extension_deleter([](STACK_OF(X509_EXTENSION) *extensions){ sk_X509_EXTENSION_free(extensions); });
    unique_ptr< STACK_OF(X509_EXTENSION), decltype(stack_of_x509_extension_deleter) > extensions(sk_X509_EXTENSION_new_null(), stack_of_x509_extension_deleter);
    if (!extensions) throw bad_alloc();

    sk_X509_EXTENSION_push(extensions.get(), extension.get());

    x509->addExtensions(extensions.get());
}
}}
