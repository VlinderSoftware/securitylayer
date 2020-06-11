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
#include "certificatesignrequest.hpp"
#include "constants.hpp"
#include "../exceptions/contract.hpp"

using namespace std;

namespace DNP3SAv6 { namespace Details { 
CertificateSignRequest::~CertificateSignRequest()
{
    X509_REQ_free(req_);
}

EVP_PKEY* CertificateSignRequest::getSubjectPublicKey() const
{
    return X509_REQ_get0_pubkey(req_);
}
unique_ptr< EC_KEY, function< void(EC_KEY*) > > CertificateSignRequest::getECDHPublicKey() const
{
    auto extensions(X509_REQ_get_extensions(req_));
    auto asn1_object_deleter([](ASN1_OBJECT *obj){ ASN1_OBJECT_free(obj); });
    unique_ptr< ASN1_OBJECT, decltype(asn1_object_deleter) > asn1(OBJ_txt2obj(DNP3_ECDH_EXTENSION_OID, 1), asn1_object_deleter);
    if (!asn1) throw bad_alloc();

    if (extensions)
    {
        int idx(0);
        X509_EXTENSION *extension(sk_X509_EXTENSION_value(extensions, idx));
        while (extension)
        {
            auto oid(X509_EXTENSION_get_object(extension));
            if (OBJ_cmp(oid, asn1.get()) != 0)
            {
                ++idx;
                extension = sk_X509_EXTENSION_value(extensions, idx);
            }
            else
            { /* found it! */
                break;
            }
        }
        if (extension)
        {
#ifndef NDEBUG
            auto oid(X509_EXTENSION_get_object(extension));
            assert(OBJ_cmp(oid, asn1.get()) == 0);
#endif
            auto der_encoded_extension_payload(X509_EXTENSION_get_data(extension));
            unsigned char const *data(der_encoded_extension_payload->data);
            auto ecdh_public_key_deleter([](ECDHPublicKey *ecdh_public_key){ ECDHPublicKey_free(ecdh_public_key); });
            unique_ptr< ECDHPublicKey, decltype(ecdh_public_key_deleter) > ecdh_public_key(d2i_ECDHPublicKey(nullptr, &data, der_encoded_extension_payload->length), ecdh_public_key_deleter);
            assert(!!ecdh_public_key);
            auto the_key(ecdh_public_key->publicKey);
            data = the_key->data;
            auto ec_key_deleter([](EC_KEY *ec_key){ EC_KEY_free(ec_key); });
            unique_ptr< EC_KEY, decltype(ec_key_deleter) > key(o2i_ECPublicKey(nullptr, &data, the_key->length), ec_key_deleter);
            return key;
        }
        else
        { /* not found */ }
    }
    else
    { /* no extensions */ }

    return unique_ptr< EC_KEY, function< void(EC_KEY*) > >();
}
X509_NAME* CertificateSignRequest::getSubjectName() const
{
    return X509_REQ_get_subject_name(req_);
}
CertificateSignRequest::CertificateSignRequest(unique_ptr< X509_REQ, std::function< void(X509_REQ*) > > &&req)
    : req_(req.release())
{
}
}}
